# gremlind

A `pppd`/`xl2tpd`-style control-plane daemon for **GRE** tunnels.

GRE (IP protocol 47) has no signaling layer of its own: a Linux GRE tunnel is
static, configured by hand on both ends with `ip tunnel add`. There is no session
negotiation, no authentication, no dynamic address assignment, no runtime setup
or teardown.

`gremlind` supplies that missing control plane. A single binary runs in either role:

- **`gremlind server`** — a *concentrator* that dynamically accepts clients,
  negotiates a session per client, provisions the GRE interface, assigns an inner
  address, and tears everything down when the client disconnects.
- **`gremlind connect`** — a *dialer* that authenticates to a server, obtains a
  session, and builds its local GRE interface from the negotiated parameters.

The design follows PPTP: a reliable **TCP control channel** carries the
handshake, authentication, MTU negotiation and keepalives, while **GRE carries
only the payload**. Binding the session to the TCP connection means a dropped
connection cleanly ends the session.

### Highlights

- **IPv6-native** (dual-stack): `ip6gre` by default, `ip_gre` for IPv4 outer
  endpoints. Inner pool defaults to a v6 prefix.
- **Real MTU negotiation**: the tunnel MTU is derived from *both* peers' outer
  MTU minus the GRE overhead, not a static config value.
- **Native GRE** whenever there is no NAT in the path. (GRE-in-UDP / FOU as a NAT
  fallback is future work.)
- **Deterministic link-locals**: every tunnel gets fixed `fe80::1` (server) /
  `fe80::2` (client), so routing protocols over the tunnel have a stable next-hop.
- **Minimal dependencies**: the data-plane talks to the kernel over a small,
  self-contained rtnetlink layer (`golang.org/x/sys/unix` only) — no third-party
  netlink library.
- HMAC challenge-response authentication over a pre-shared key (per-client secrets
  supported) — the secret never crosses the wire.
- **Seamless roaming**: a client that changes its outer IP (DSL reconnect,
  Wi-Fi↔mobile) automatically reconnects and keeps the *same* inner address via
  sticky per-client leases; the server evicts the stale session and just updates
  the GRE remote.
- `pppd`-style up/down hooks and a `status` admin socket.

## Build & run (Nix)

The flake carries the whole toolchain — no system Go required.

```sh
nix develop            # dev shell: go, gopls, golangci-lint, iproute2
nix build              # reproducible binary at ./result/bin/gremlind
nix run . -- server -c configs/gremlind.example.yaml
```

## Usage

```
gremlind server  [-c config.yaml] [-v]
gremlind connect <server:port> [-c config.yaml] [-id ID] [-secret S] [-v]
gremlind status  [-s /run/gremlind.sock]
```

Both roles require `CAP_NET_ADMIN` (they create GRE interfaces via netlink).

See [configs/gremlind.example.yaml](configs/gremlind.example.yaml) for a fully
commented configuration.

### Up/down hooks

When a tunnel comes up or down, the configured `hooks.up` / `hooks.down` script
runs with details in the environment: `GREMLIND_IFACE`, `GREMLIND_CLIENT_ID`,
`GREMLIND_INNER_LOCAL`, `GREMLIND_INNER_PEER`, `GREMLIND_OUTER_LOCAL`,
`GREMLIND_OUTER_PEER`, `GREMLIND_GRE_KEY`, `GREMLIND_MTU`, `GREMLIND_EVENT`.

## Deploying on NixOS

The flake exports `nixosModules.gremlind`:

```nix
{
  imports = [ gremlind.nixosModules.gremlind ];
  services.gremlind = {
    enable = true;
    role = "server";                 # or "connect"
    configFile = ./gremlind.yaml;
    # connectTo = "[2001:db8::10]:4747";  # required when role = "connect"
  };
}
```

The service runs with `AmbientCapabilities = CAP_NET_ADMIN` under a dynamic user.

## Testing

```sh
nix develop --command go test ./...        # unit tests (codec, ippool, session, handshake)
nix develop --command ./scripts/e2e.sh ./result/bin/gremlind
```

`scripts/e2e.sh` is a **rootless** end-to-end test: it spins up two network
namespaces joined by a veth pair (via user namespaces, no root needed), runs the
server and a client, and verifies a ping through the tunnel plus `status`, the
up-hook, **roaming** (changing the client's outer IP and confirming the tunnel
recovers with the same inner IP), and server-side teardown on disconnect.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/gremlind` | CLI: `server`, `connect`, `status` |
| `internal/control` | Control protocol: wire format, codec, state machines |
| `internal/session` | Session registry, MTU negotiation, data-plane orchestration |
| `internal/gre` | GRE interfaces via a self-contained rtnetlink layer (`ip6gre`/`gre`) |
| `internal/ippool` | Inner-address allocation |
| `internal/auth` | HMAC challenge-response |
| `internal/hooks` | up/down hook runner |
| `internal/admin` | `status` unix-socket API |

## Status & roadmap

Working: dynamic sessions, IPv6-native data-plane, MTU negotiation, PSK auth,
keepalive/dead-peer detection, seamless roaming (reconnect + sticky inner
leases), hooks, `status`, NixOS module.

Future work: GRE-in-UDP/FOU for NAT traversal; TLS-wrapped control channel;
multiple sessions per control connection (GRE-key multiplexing); lease TTLs and
server-outer auto-detection.
