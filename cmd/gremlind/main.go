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
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"gremlind/internal/admin"
	"gremlind/internal/config"
	"gremlind/internal/control"
	"gremlind/internal/gre"
	"gremlind/internal/hardening"
	"gremlind/internal/healthcheck"
	"gremlind/internal/hooks"
	"gremlind/internal/ippool"
	"gremlind/internal/mssclamp"
	"gremlind/internal/provisionrpc"
	"gremlind/internal/session"

	"golang.org/x/sys/unix"
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
	case "netlinkd":
		return runNetlinkd(rest)
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
  gremlind server   [-c config.yaml] [-v]
  gremlind connect  <server:port> [-c config.yaml] [-id ID] [-secret S] [-secret-env ENV] [-v]
  gremlind netlinkd -s /run/gremlind-netlink.sock [-mode 0600] [-group GROUP] [-gre-local ADDR] [-v]
  gremlind status   [-s /run/gremlind.sock]
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
	hardening.Apply(log)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	warnLooseConfigPerms(log, *cfgPath)
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
	// FOU already demultiplexes by UDP port + outer addresses, so GRE key and
	// sequence fields are redundant extra bytes. Force both off regardless of
	// gre_key/gre_seq whenever GRE is wrapped in UDP.
	useGREKey := cfg.GREKeyEnabled()
	useGRESeq := cfg.GRESeqEnabled()
	if cfg.FOUPort != 0 {
		useGREKey = false
		useGRESeq = false
	}
	sessCfg := session.Config{
		Log:         log,
		Pool:        pool,
		ServerInner: serverInner,
		GRELocal:    greLocal,
		MTUCap:      cfg.MTU,
		UseGREKey:   useGREKey,
		UseGRESeq:   useGRESeq,
		UpHook:      cfg.Hooks.Up,
		DownHook:    cfg.Hooks.Down,
		LeaseTTL:    cfg.LeaseTTL.Std(),
		FOUPort:     cfg.FOUPort,
		MSSClamp:    cfg.MSSClamp,
	}
	if cfg.FOUPort != 0 {
		if err := gre.EnsureFOUReceive(cfg.FOUPort); err != nil {
			return fmt.Errorf("server: %w", err)
		}
		log.Info("gre-over-udp (fou) enabled, gre key and sequence fields forced off", "port", cfg.FOUPort)
	}
	var mgr *session.Manager
	if cfg.NetlinkSocket != "" {
		broker := provisionrpc.Client{Path: cfg.NetlinkSocket}
		if mtu, err := broker.OuterMTU(greLocal); err == nil {
			sessCfg.OuterMTU = mtu
		} else {
			log.Warn("could not detect outer MTU via netlink broker, assuming 1500", "err", err)
			sessCfg.OuterMTU = 1500
		}
		mgr = session.NewWithProvisioner(sessCfg, broker)
		log.Info("using netlink broker", "socket", cfg.NetlinkSocket)
	} else {
		mgr = session.New(sessCfg)
	}

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

type greProvisioner struct{}

func (greProvisioner) Ensure(p gre.Params) error { return gre.Ensure(p) }
func (greProvisioner) Remove(name string) error  { return gre.Remove(name) }

func runNetlinkd(args []string) error {
	fs := flag.NewFlagSet("netlinkd", flag.ContinueOnError)
	sock := fs.String("s", "", "unix socket path for provisioning RPC")
	modeFlag := fs.String("mode", "0600", "provisioning socket mode (octal, e.g. 0600 or 0660)")
	group := fs.String("group", "", "optional provisioning socket group")
	greLocalFlag := fs.String("gre-local", "", "optional allowed GRE local outer address")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sock == "" {
		return fmt.Errorf("netlinkd: -s /run/gremlind-netlink.sock is required")
	}
	var greLocal netip.Addr
	if *greLocalFlag != "" {
		addr, err := netip.ParseAddr(*greLocalFlag)
		if err != nil {
			return fmt.Errorf("netlinkd: invalid -gre-local %q: %w", *greLocalFlag, err)
		}
		greLocal = addr
	}
	mode, err := parseFileMode(*modeFlag)
	if err != nil {
		return fmt.Errorf("netlinkd: %w", err)
	}
	log := newLogger(*verbose)
	hardening.Apply(log)
	if removed, err := gre.RemovePrefix("grem"); err != nil {
		return fmt.Errorf("netlinkd: cleanup stale grem interfaces: %w", err)
	} else if len(removed) > 0 {
		log.Info("removed stale gremlind interfaces", "ifaces", removed)
	}
	ctx, stop := signalContext()
	defer stop()
	return (&provisionrpc.Server{
		Log:      log,
		Path:     *sock,
		Mode:     mode,
		Group:    *group,
		GRELocal: greLocal,
		Prov:     greProvisioner{},
		OuterMTU: gre.OuterMTU,
	}).Serve(ctx)
}

func warnLooseConfigPerms(log *slog.Logger, path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if st.Mode().Perm()&0o077 != 0 {
		log.Warn("config file is readable by group/others; secrets should be private", "path", path, "mode", fmt.Sprintf("%04o", st.Mode().Perm()))
	}
}

func parseFileMode(s string) (os.FileMode, error) {
	mode, err := strconv.ParseUint(s, 8, 32)
	if err != nil || mode > 0o777 {
		if err == nil {
			err = fmt.Errorf("mode exceeds 0777")
		}
		return 0, fmt.Errorf("invalid socket mode %q: %w", s, err)
	}
	return os.FileMode(mode), nil
}

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	cfgPath := fs.String("c", "", "path to config file")
	idFlag := fs.String("id", "", "client id (overrides config)")
	secretFlag := fs.String("secret", "", "shared secret (overrides env/config; prefer -secret-env or GREMLIND_SECRET)")
	secretEnv := fs.String("secret-env", "GREMLIND_SECRET", "environment variable containing shared secret")
	ifaceFlag := fs.String("iface", "", "GRE tunnel interface name (overrides config; default grem0)")
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
	hardening.Apply(log)

	cfg := &config.Config{}
	if *cfgPath != "" {
		var err error
		if cfg, err = config.Load(*cfgPath); err != nil {
			return err
		}
		warnLooseConfigPerms(log, *cfgPath)
	}
	// Ensure keepalive durations are non-zero even without a config file; a zero
	// interval would panic time.NewTicker in the keepalive loop.
	cfg.ApplyDefaults()
	clientID := pick(*idFlag, cfg.Client.ID)
	secret := secretFromInputs(*secretFlag, *secretEnv, cfg)
	if clientID == "" || secret == "" {
		return fmt.Errorf("connect: client id and secret are required (via -id and GREMLIND_SECRET/-secret-env, -secret, or config)")
	}
	iface := pick(*ifaceFlag, cfg.Client.Iface)
	if len(iface) > unix.IFNAMSIZ-1 {
		return fmt.Errorf("connect: interface name %q longer than %d chars", iface, unix.IFNAMSIZ-1)
	}
	if cfg.FOUPort != 0 {
		if err := gre.EnsureFOUReceive(cfg.FOUPort); err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		log.Info("gre-over-udp (fou) enabled", "port", cfg.FOUPort)
	}

	ctx, stop := signalContext()
	defer stop()
	return runDialer(ctx, log, cfg, server, clientID, secret, iface)
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
func runDialer(ctx context.Context, log *slog.Logger, cfg *config.Config, server, clientID, secret, iface string) error {
	var lastInner netip.Addr
	backoff := minBackoff

	for {
		if ctx.Err() != nil {
			return nil
		}
		inner, established, err := dialOnce(ctx, log, cfg, server, clientID, secret, iface, lastInner)
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
func dialOnce(ctx context.Context, log *slog.Logger, cfg *config.Config, server, clientID, secret, ifName string, requestedInner netip.Addr) (netip.Addr, bool, error) {
	var d net.Dialer
	if local, err := chooseSourceAddress(ctx, server, cfg.Client.SourceRules, cfg.Client.SourceFallback); err != nil {
		return netip.Addr{}, false, err
	} else if local.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: net.IP(local.AsSlice())}
		log.Debug("using configured source address", "addr", local)
	}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()

	clientOuter := localOuter(conn)
	if !clientOuter.IsValid() {
		return netip.Addr{}, false, fmt.Errorf("could not determine local outer address")
	}
	serverOuter := remoteOuter(conn)
	outerMTU := 1500
	var prov interface {
		Ensure(gre.Params) error
		Remove(string) error
	} = greProvisioner{}
	if cfg.NetlinkSocket != "" {
		broker := provisionrpc.Client{Path: cfg.NetlinkSocket}
		prov = broker
		var err error
		if serverOuter.IsValid() {
			outerMTU, err = broker.OuterMTUForPath(clientOuter, serverOuter)
		} else {
			outerMTU, err = broker.OuterMTU(clientOuter)
		}
		if err != nil {
			log.Debug("outer MTU detection via netlink broker failed, assuming 1500", "err", err)
			outerMTU = 1500
		}
	} else if serverOuter.IsValid() {
		if m, err := gre.OuterMTUForPath(clientOuter, serverOuter); err == nil {
			outerMTU = m
		} else if m, err := gre.OuterMTU(clientOuter); err == nil {
			outerMTU = m
		} else {
			log.Debug("outer MTU detection failed, assuming 1500", "err", err)
		}
	} else if m, err := gre.OuterMTU(clientOuter); err == nil {
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
	effectiveGREKey := sess.GREKey
	effectiveGRESeq := sess.TunnelFlags&control.TunnelFlagGRESeq != 0
	if cfg.FOUPort != 0 {
		effectiveGREKey = 0
		effectiveGRESeq = false
	}
	log.Info("session established",
		"inner", sess.ClientInner, "server_inner", sess.ServerInner,
		"gre_key", effectiveGREKey, "gre_seq", effectiveGRESeq, "mtu", sess.MTU)

	if err := prov.Ensure(gre.Params{
		Name:       ifName,
		Local:      clientOuter,
		Remote:     sess.ServerOuter,
		Key:        effectiveGREKey,
		Seq:        effectiveGRESeq,
		MTU:        int(sess.MTU),
		InnerLocal: sess.ClientInner,
		InnerPeer:  sess.ServerInner,
		LinkLocal:  gre.ClientLinkLocal,
		FOUSport:   cfg.FOUPort,
		FOUDport:   cfg.FOUPort,
	}); err != nil {
		return sess.ClientInner, true, fmt.Errorf("build local GRE interface: %w", err)
	}
	if err := mssclamp.Apply(ctx, log, cfg.MSSClamp, ifName, int(sess.MTU)); err != nil {
		_ = prov.Remove(ifName)
		return sess.ClientInner, true, fmt.Errorf("install mss clamp rules: %w", err)
	}
	log.Info("tunnel interface up", "iface", ifName, "addr", sess.ClientInner)

	hookInfo := hooks.Info{
		Iface:      ifName,
		ClientID:   clientID,
		InnerLocal: sess.ClientInner,
		InnerPeer:  sess.ServerInner,
		OuterLocal: clientOuter,
		OuterPeer:  sess.ServerOuter,
		GREKey:     effectiveGREKey,
		MTU:        int(sess.MTU),
	}
	upInfo := hookInfo
	upInfo.Event = "up"
	hooks.Run(ctx, log, cfg.Hooks.Up, upInfo)

	defer func() {
		if err := mssclamp.Remove(context.Background(), log, cfg.MSSClamp, ifName, int(sess.MTU)); err != nil {
			log.Warn("mss clamp cleanup failed", "iface", ifName, "err", err)
		}
		if err := prov.Remove(ifName); err != nil {
			log.Warn("interface cleanup failed", "iface", ifName, "err", err)
		} else {
			log.Info("tunnel interface removed", "iface", ifName)
		}
		downInfo := hookInfo
		downInfo.Event = "down"
		hooks.Run(context.Background(), log, cfg.Hooks.Down, downInfo)
	}()

	return sess.ClientInner, true, runSessionLoops(ctx, log, cfg, cl, conn, ifName, sess.ServerInner)
}

func runSessionLoops(ctx context.Context, log *slog.Logger, cfg *config.Config, cl *control.Client, conn net.Conn, ifName string, innerPeer netip.Addr) error {
	if !cfg.HealthCheck.Enabled {
		return cl.KeepaliveLoop(ctx, conn)
	}
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- cl.KeepaliveLoop(loopCtx, conn) }()
	go func() { errCh <- healthcheck.Loop(loopCtx, log, cfg.HealthCheck, ifName, innerPeer) }()

	err := <-errCh
	cancel()
	if err == nil && ctx.Err() != nil {
		return nil
	}
	return err
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
	return tcpAddrIP(conn.LocalAddr())
}

// remoteOuter extracts the peer IP of an established connection.
func remoteOuter(conn net.Conn) netip.Addr {
	return tcpAddrIP(conn.RemoteAddr())
}

func tcpAddrIP(addr net.Addr) netip.Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func chooseSourceAddress(ctx context.Context, server string, rules []config.SourceRule, fallback string) (netip.Addr, error) {
	if len(rules) == 0 {
		return netip.Addr{}, nil
	}
	serverAddrs, err := resolveServerAddrs(ctx, server)
	if err != nil {
		return netip.Addr{}, err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("list interfaces for source selection: %w", err)
	}
	for i, rule := range rules {
		addr, err := chooseSourceAddressFromRule(ifaces, serverAddrs, rule)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("client.source_rules[%d]: %w", i, err)
		}
		if addr.IsValid() {
			return addr, nil
		}
	}
	if fallback == "kernel" {
		return netip.Addr{}, nil
	}
	return netip.Addr{}, fmt.Errorf("no local source address matched client.source_rules for %s", server)
}

func resolveServerAddrs(ctx context.Context, server string) ([]netip.Addr, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", server, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve server %q for source selection: %w", host, err)
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve server %q for source selection: no addresses", host)
	}
	return out, nil
}

func chooseSourceAddressFromRule(ifaces []net.Interface, serverAddrs []netip.Addr, rule config.SourceRule) (netip.Addr, error) {
	families, applies, err := sourceRuleFamilies(serverAddrs, rule)
	if err != nil || !applies {
		return netip.Addr{}, err
	}
	allowedIfaces := map[string]bool{}
	for _, name := range rule.Ifaces {
		name = strings.TrimSpace(name)
		if name != "" {
			allowedIfaces[name] = true
		}
	}
	includes, err := parsePrefixes("include_subnets", rule.IncludeSubnets)
	if err != nil {
		return netip.Addr{}, err
	}
	excludes, err := parsePrefixes("exclude_subnets", rule.ExcludeSubnets)
	if err != nil {
		return netip.Addr{}, err
	}
	seenAllowed := map[string]bool{}
	for _, iface := range ifaces {
		if len(allowedIfaces) > 0 {
			if !allowedIfaces[iface.Name] {
				continue
			}
			seenAllowed[iface.Name] = true
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			addr, ok := ifaceAddrIP(raw)
			if !ok || !families[addr.Is6()] || !includedSource(addr, includes) || excludedSource(addr, excludes) {
				continue
			}
			return addr, nil
		}
	}
	for name := range allowedIfaces {
		if !seenAllowed[name] {
			return netip.Addr{}, fmt.Errorf("interface %q not found", name)
		}
	}
	return netip.Addr{}, nil
}

func sourceRuleFamilies(serverAddrs []netip.Addr, rule config.SourceRule) (map[bool]bool, bool, error) {
	serverMatches, err := parsePrefixes("match_server_subnets", rule.MatchServerSubnets)
	if err != nil {
		return nil, false, err
	}
	families := map[bool]bool{}
	for _, addr := range serverAddrs {
		if !includedSource(addr, serverMatches) {
			continue
		}
		families[addr.Is6()] = true
	}
	if len(families) == 0 {
		return nil, false, nil
	}
	switch rule.Family {
	case "ipv4":
		families[true] = false
	case "ipv6":
		families[false] = false
	}
	return families, families[false] || families[true], nil
}

func parsePrefixes(field string, raw []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid %s prefix %q: %w", field, s, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

func ifaceAddrIP(raw net.Addr) (netip.Addr, bool) {
	prefix, err := netip.ParsePrefix(raw.String())
	if err != nil {
		return netip.Addr{}, false
	}
	addr := prefix.Addr().Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, false
	}
	return addr, true
}

func includedSource(addr netip.Addr, includes []netip.Prefix) bool {
	if len(includes) == 0 {
		return true
	}
	for _, p := range includes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func excludedSource(addr netip.Addr, excludes []netip.Prefix) bool {
	for _, p := range excludes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
