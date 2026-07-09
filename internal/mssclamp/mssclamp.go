package mssclamp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"

	"gremlind/internal/config"
)

const defaultNFTPriority = "mangle"

// Apply installs MSS clamping rules for iface according to cfg. It is best
// effort/idempotent: existing gremlind-owned rules for this iface are removed
// before new ones are added. tunnelMTU is the negotiated tunnel interface MTU;
// it is used when mss_mode = tunnel_mtu.
func Apply(ctx context.Context, log *slog.Logger, cfg config.MSSClamp, iface string, tunnelMTU int) error {
	if !cfg.Enabled {
		return nil
	}
	cfg = cfg.WithDefaults()
	specs := ruleSpecs(cfg.Direction)
	if len(specs) == 0 {
		return fmt.Errorf("invalid mss_clamp.direction %q", cfg.Direction)
	}
	if err := Remove(ctx, log, cfg, iface, tunnelMTU); err != nil {
		log.Debug("mss clamp pre-clean failed", "iface", iface, "err", err)
	}
	for _, spec := range specs {
		var err error
		switch cfg.Backend {
		case "nftables":
			err = applyNFT(ctx, cfg, iface, spec, tunnelMTU)
		case "iptables":
			err = applyIPTables(ctx, cfg, iface, spec, tunnelMTU)
		default:
			err = fmt.Errorf("invalid mss_clamp.backend %q", cfg.Backend)
		}
		if err != nil {
			return err
		}
	}
	log.Debug("mss clamp rules installed", "backend", cfg.Backend, "iface", iface, "direction", cfg.Direction, "mtu", tunnelMTU)
	return nil
}

// Remove removes gremlind-owned MSS clamping rules for iface.
func Remove(ctx context.Context, log *slog.Logger, cfg config.MSSClamp, iface string, tunnelMTU int) error {
	if !cfg.Enabled {
		return nil
	}
	cfg = cfg.WithDefaults()
	for _, spec := range ruleSpecs(cfg.Direction) {
		var err error
		switch cfg.Backend {
		case "nftables":
			err = removeNFT(ctx, cfg, iface, spec)
		case "iptables":
			err = removeIPTables(ctx, cfg, iface, spec, tunnelMTU)
		default:
			err = fmt.Errorf("invalid mss_clamp.backend %q", cfg.Backend)
		}
		if err != nil {
			return err
		}
	}
	log.Debug("mss clamp rules removed", "backend", cfg.Backend, "iface", iface, "direction", cfg.Direction)
	return nil
}

type directionSpec struct {
	name string
	nft  string
	ipt  string
}

func ruleSpecs(direction string) []directionSpec {
	switch direction {
	case "", "out":
		return []directionSpec{{name: "out", nft: "oifname", ipt: "-o"}}
	case "in":
		return []directionSpec{{name: "in", nft: "iifname", ipt: "-i"}}
	case "both":
		return []directionSpec{{name: "out", nft: "oifname", ipt: "-o"}, {name: "in", nft: "iifname", ipt: "-i"}}
	default:
		return nil
	}
}

func applyNFT(ctx context.Context, cfg config.MSSClamp, iface string, spec directionSpec, tunnelMTU int) error {
	if cfg.NFTManageTable {
		if err := ensureNFTTable(ctx, cfg); err != nil {
			return err
		}
		if err := ensureNFTChain(ctx, cfg); err != nil {
			return err
		}
	}
	for _, proto := range protocolSpecs() {
		args := []string{"add", "rule", cfg.NFTFamily, cfg.NFTTable, cfg.NFTChain, spec.nft, iface}
		args = append(args, proto.nftMatch...)
		args = append(args, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set")
		if mss := proto.mss(cfg, tunnelMTU); mss > 0 {
			args = append(args, strconv.Itoa(mss))
		} else {
			args = append(args, proto.nftPMTU...)
		}
		args = append(args, "comment", marker(iface, spec.name, proto.name))
		if err := run(ctx, "nft", args...); err != nil {
			return err
		}
	}
	return nil
}

func removeNFT(ctx context.Context, cfg config.MSSClamp, iface string, spec directionSpec) error {
	out, err := output(ctx, "nft", "-a", "list", "chain", cfg.NFTFamily, cfg.NFTTable, cfg.NFTChain)
	if err != nil {
		return nil // absent table/chain is already clean
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "`+markerPrefix(iface, spec.name)) {
			continue
		}
		handle := nftHandle(line)
		if handle == "" {
			continue
		}
		if err := run(ctx, "nft", "delete", "rule", cfg.NFTFamily, cfg.NFTTable, cfg.NFTChain, "handle", handle); err != nil {
			return err
		}
	}
	return nil
}

func ensureNFTTable(ctx context.Context, cfg config.MSSClamp) error {
	if err := run(ctx, "nft", "list", "table", cfg.NFTFamily, cfg.NFTTable); err == nil {
		return nil
	}
	return run(ctx, "nft", "add", "table", cfg.NFTFamily, cfg.NFTTable)
}

func ensureNFTChain(ctx context.Context, cfg config.MSSClamp) error {
	if err := run(ctx, "nft", "list", "chain", cfg.NFTFamily, cfg.NFTTable, cfg.NFTChain); err == nil {
		return nil
	}
	return run(ctx, "nft", "add", "chain", cfg.NFTFamily, cfg.NFTTable, cfg.NFTChain,
		"{", "type", "filter", "hook", "forward", "priority", defaultNFTPriority+";", "policy", "accept;", "}")
}

func nftHandle(line string) string {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "handle" {
			return fields[i+1]
		}
	}
	return ""
}

func applyIPTables(ctx context.Context, cfg config.MSSClamp, iface string, spec directionSpec, tunnelMTU int) error {
	for _, proto := range protocolSpecs() {
		rule := iptablesRule(cfg, iface, spec, proto, tunnelMTU)
		if err := run(ctx, proto.iptables, append([]string{"-t", "mangle", "-C", cfg.IPTablesChain}, rule...)...); err == nil {
			continue
		}
		if err := run(ctx, proto.iptables, append([]string{"-t", "mangle", "-A", cfg.IPTablesChain}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

func removeIPTables(ctx context.Context, cfg config.MSSClamp, iface string, spec directionSpec, tunnelMTU int) error {
	for _, proto := range protocolSpecs() {
		rule := iptablesRule(cfg, iface, spec, proto, tunnelMTU)
		for {
			if err := run(ctx, proto.iptables, append([]string{"-t", "mangle", "-D", cfg.IPTablesChain}, rule...)...); err != nil {
				break
			}
		}
	}
	return nil
}

type protocolSpec struct {
	name     string
	iptables string
	nftMatch []string
	nftPMTU  []string
	mss      func(config.MSSClamp, int) int
}

func protocolSpecs() []protocolSpec {
	return []protocolSpec{
		{
			name:     "v4",
			iptables: "iptables",
			nftMatch: []string{"ip", "protocol", "tcp"},
			nftPMTU:  []string{"rt", "mtu"},
			mss: func(cfg config.MSSClamp, tunnelMTU int) int {
				if cfg.MSS4 > 0 {
					return cfg.MSS4
				}
				if cfg.MSS > 0 {
					return cfg.MSS
				}
				if cfg.MSSMode == "tunnel_mtu" && tunnelMTU > 40 {
					return tunnelMTU - 40
				}
				return 0
			},
		},
		{
			name:     "v6",
			iptables: "ip6tables",
			nftMatch: []string{"ip6", "nexthdr", "tcp"},
			nftPMTU:  []string{"rt6", "mtu"},
			mss: func(cfg config.MSSClamp, tunnelMTU int) int {
				if cfg.MSS6 > 0 {
					return cfg.MSS6
				}
				if cfg.MSS > 0 {
					return cfg.MSS
				}
				if cfg.MSSMode == "tunnel_mtu" && tunnelMTU > 60 {
					return tunnelMTU - 60
				}
				return 0
			},
		},
	}
}

func iptablesRule(cfg config.MSSClamp, iface string, spec directionSpec, proto protocolSpec, tunnelMTU int) []string {
	rule := []string{spec.ipt, iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", marker(iface, spec.name, proto.name), "-j", "TCPMSS"}
	if mss := proto.mss(cfg, tunnelMTU); mss > 0 {
		return append(rule, "--set-mss", strconv.Itoa(mss))
	}
	return append(rule, "--clamp-mss-to-pmtu")
}

func marker(iface, direction, proto string) string { return markerPrefix(iface, direction) + proto }
func markerPrefix(iface, direction string) string  { return "gremlind:" + iface + ":" + direction + ":" }

func run(ctx context.Context, name string, args ...string) error {
	_, err := output(ctx, name, args...)
	return err
}

func output(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
