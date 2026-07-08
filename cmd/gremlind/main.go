// Command gremlind is a control-plane daemon for GRE tunnels. A single binary
// runs as either a concentrator (server) that dynamically accepts GRE clients,
// or a dialer (connect) that establishes a session against such a server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"gremlind/internal/admin"
	"gremlind/internal/config"
	"gremlind/internal/control"
	"gremlind/internal/gre"
	"gremlind/internal/hooks"
	"gremlind/internal/ippool"
	"gremlind/internal/session"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gremlind: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing subcommand")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "server":
		return runServer(rest)
	case "connect":
		return runConnect(rest)
	case "status":
		return runStatus(rest)
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gremlind — control-plane daemon for GRE tunnels

usage:
  gremlind server  [-c config.yaml] [-v]
  gremlind connect <server:port> [-c config.yaml] [-id ID] [-secret S] [-secret-env ENV] [-v]
  gremlind status  [-s /run/gremlind.sock]
`)
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	cfgPath := fs.String("c", "", "path to config file")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("server: -c config.yaml is required")
	}

	log := newLogger(*verbose)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.ValidateServer(); err != nil {
		return err
	}

	greLocal := netip.MustParseAddr(cfg.GRELocal) // validated by ValidateServer
	serverInner := netip.MustParseAddr(cfg.ServerInner)
	poolPrefix := netip.MustParsePrefix(cfg.InnerPool)

	pool, err := ippool.New(poolPrefix, serverInner)
	if err != nil {
		return err
	}
	mgr := session.New(session.Config{
		Log:         log,
		Pool:        pool,
		ServerInner: serverInner,
		GRELocal:    greLocal,
		MTUCap:      cfg.MTU,
		UseGREKey:   cfg.GREKeyEnabled(),
		UpHook:      cfg.Hooks.Up,
		DownHook:    cfg.Hooks.Down,
		LeaseTTL:    cfg.LeaseTTL.Std(),
	})

	srv := &control.Server{
		Log:                  log,
		PSK:                  cfg.Auth.PSK,
		Clients:              cfg.Auth.Clients,
		Establisher:          mgr,
		KeepaliveTimeout:     cfg.KeepaliveTimeout.Std(),
		MaxPendingHandshakes: cfg.MaxPendingHandshakes,
		MaxPendingPerIP:      cfg.MaxPendingPerIP,
		DecoyRedirect:        cfg.DecoyRedirect,
		GremlinMustHide:      cfg.GremlinMustHide,
	}

	ctx, stop := signalContext()
	defer stop()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	if cfg.AdminSocket != "" {
		adminMode, err := cfg.AdminMode()
		if err != nil {
			return err
		}
		go func() {
			if err := admin.ServeWithOptions(ctx, log, admin.Options{
				Path:  cfg.AdminSocket,
				Mode:  adminMode,
				Group: cfg.AdminSocketGroup,
			}, mgr.Sessions); err != nil {
				log.Warn("admin socket stopped", "err", err)
			}
		}()
	}

	log.Info("gremlind server listening",
		"listen", cfg.Listen, "gre_local", greLocal, "inner_pool", cfg.InnerPool)
	return srv.Serve(ctx, ln)
}

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	cfgPath := fs.String("c", "", "path to config file")
	idFlag := fs.String("id", "", "client id (overrides config)")
	secretFlag := fs.String("secret", "", "shared secret (overrides env/config; prefer -secret-env or GREMLIND_SECRET)")
	secretEnv := fs.String("secret-env", "GREMLIND_SECRET", "environment variable containing shared secret")
	verbose := fs.Bool("v", false, "verbose (debug) logging")

	// Accept the <server:port> positional argument in any position by pulling
	// the first non-flag token out before parsing the remaining flags (the
	// stdlib flag package stops at the first positional argument otherwise).
	server, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		server, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if server == "" {
		server = fs.Arg(0)
	}
	if server == "" {
		return fmt.Errorf("connect: <server:port> argument is required")
	}

	log := newLogger(*verbose)

	cfg := &config.Config{}
	if *cfgPath != "" {
		var err error
		if cfg, err = config.Load(*cfgPath); err != nil {
			return err
		}
	}
	// Ensure keepalive durations are non-zero even without a config file; a zero
	// interval would panic time.NewTicker in the keepalive loop.
	cfg.ApplyDefaults()
	clientID := pick(*idFlag, cfg.Client.ID)
	secret := secretFromInputs(*secretFlag, *secretEnv, cfg)
	if clientID == "" || secret == "" {
		return fmt.Errorf("connect: client id and secret are required (via -id and GREMLIND_SECRET/-secret-env, -secret, or config)")
	}

	ctx, stop := signalContext()
	defer stop()
	return runDialer(ctx, log, cfg, server, clientID, secret)
}

// reconnect backoff bounds.
const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// runDialer keeps a session up across outer-IP changes and transient failures:
// it reconnects with exponential backoff and re-requests its previous inner
// address so the server's sticky lease hands back the same IP (seamless roaming).
// It stops on context cancellation or a permanent rejection (bad credentials).
func runDialer(ctx context.Context, log *slog.Logger, cfg *config.Config, server, clientID, secret string) error {
	var lastInner netip.Addr
	backoff := minBackoff

	for {
		if ctx.Err() != nil {
			return nil
		}
		inner, established, err := dialOnce(ctx, log, cfg, server, clientID, secret, lastInner)
		if inner.IsValid() {
			lastInner = inner // remember for sticky reconnect
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, control.ErrRejected) {
			return err // permanent: don't hammer the server
		}
		if established {
			backoff = minBackoff // a real session ran; reset backoff
		}
		log.Warn("connection lost, reconnecting", "err", err, "retry_in", backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// dialOnce runs a single connect→session→keepalive cycle. It returns the inner
// address that was assigned (for sticky reconnect) and whether a session was
// actually established.
func dialOnce(ctx context.Context, log *slog.Logger, cfg *config.Config, server, clientID, secret string, requestedInner netip.Addr) (netip.Addr, bool, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()

	clientOuter := localOuter(conn)
	if !clientOuter.IsValid() {
		return netip.Addr{}, false, fmt.Errorf("could not determine local outer address")
	}
	outerMTU := 1500
	if m, err := gre.OuterMTU(clientOuter); err == nil {
		outerMTU = m
	} else {
		log.Debug("outer MTU detection failed, assuming 1500", "err", err)
	}

	cl := &control.Client{
		Log:               log,
		ClientID:          clientID,
		Secret:            secret,
		OuterMTU:          uint16(outerMTU),
		RequestedInner:    requestedInner,
		KeepaliveInterval: cfg.KeepaliveInterval.Std(),
		KeepaliveTimeout:  cfg.KeepaliveTimeout.Std(),
	}

	sess, err := cl.Handshake(conn)
	if err != nil {
		return netip.Addr{}, false, err
	}
	log.Info("session established",
		"inner", sess.ClientInner, "server_inner", sess.ServerInner,
		"gre_key", sess.GREKey, "mtu", sess.MTU)

	const ifName = "grem0"
	if err := gre.Ensure(gre.Params{
		Name:       ifName,
		Local:      clientOuter,
		Remote:     sess.ServerOuter,
		Key:        sess.GREKey,
		MTU:        int(sess.MTU),
		InnerLocal: sess.ClientInner,
		InnerPeer:  sess.ServerInner,
		LinkLocal:  gre.ClientLinkLocal,
	}); err != nil {
		return sess.ClientInner, true, fmt.Errorf("build local GRE interface: %w", err)
	}
	log.Info("tunnel interface up", "iface", ifName, "addr", sess.ClientInner)

	hookInfo := hooks.Info{
		Iface:      ifName,
		ClientID:   clientID,
		InnerLocal: sess.ClientInner,
		InnerPeer:  sess.ServerInner,
		OuterLocal: clientOuter,
		OuterPeer:  sess.ServerOuter,
		GREKey:     sess.GREKey,
		MTU:        int(sess.MTU),
	}
	upInfo := hookInfo
	upInfo.Event = "up"
	hooks.Run(ctx, log, cfg.Hooks.Up, upInfo)

	defer func() {
		if err := gre.Remove(ifName); err != nil {
			log.Warn("interface cleanup failed", "iface", ifName, "err", err)
		} else {
			log.Info("tunnel interface removed", "iface", ifName)
		}
		downInfo := hookInfo
		downInfo.Event = "down"
		hooks.Run(context.Background(), log, cfg.Hooks.Down, downInfo)
	}()

	return sess.ClientInner, true, cl.KeepaliveLoop(ctx, conn)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	sock := fs.String("s", "/run/gremlind.sock", "admin socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	entries, err := admin.Query(*sock)
	if err != nil {
		return fmt.Errorf("query admin socket %s: %w", *sock, err)
	}
	if len(entries) == 0 {
		fmt.Println("no active sessions")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tIFACE\tINNER\tOUTER\tKEY\tMTU\tSINCE")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			e.ClientID, e.IfName, e.ClientInner, e.ClientOuter, e.GREKey, e.MTU,
			e.Since.Format(time.RFC3339))
	}
	return tw.Flush()
}

// pick returns the first non-empty string.
func pick(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// secretFromInputs resolves the client secret without requiring it to appear in
// the process command line. Precedence is: explicit -secret flag, configured
// environment variable, client.secret, then legacy auth.psk fallback.
func secretFromInputs(secretFlag, secretEnv string, cfg *config.Config) string {
	if secretFlag != "" {
		return secretFlag
	}
	if secretEnv != "" {
		if v := os.Getenv(secretEnv); v != "" {
			return v
		}
	}
	return pick(cfg.Client.Secret, cfg.Auth.PSK)
}

// localOuter extracts the local IP of an established connection.
func localOuter(conn net.Conn) netip.Addr {
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}
