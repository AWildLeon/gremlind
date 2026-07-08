#!/usr/bin/env bash
# End-to-end test for gremlind, fully rootless via user+net namespaces.
#
#   scripts/e2e.sh /path/to/gremlind
#
# It creates a veth pair spanning two network namespaces (server + client),
# runs `gremlind server` on one side and `gremlind connect` on the other, then
# pings the server's inner address through the negotiated GRE tunnel.
#
# The client namespace is created via a holder process and entered with nsenter,
# so no writable /run/netns (i.e. no real root) is required.
set -euo pipefail

# Re-exec inside fresh user/net namespaces so an unprivileged user gets
# CAP_NET_ADMIN within them. BIN is carried across the re-exec via the env.
if [[ -z "${GREMLIND_E2E_INNER:-}" ]]; then
  BIN="${1:-}"
  if [[ -z "$BIN" ]]; then
    echo "usage: $0 /path/to/gremlind" >&2
    exit 2
  fi
  BIN="$(readlink -f "$BIN")"
  exec unshare --user --map-root-user --net --fork \
    env GREMLIND_E2E_INNER=1 BIN="$BIN" "$(readlink -f "$0")"
fi
BIN="${BIN:?internal: BIN not set after re-exec}"

SRV_OUTER="2001:db8::10"
CLI_OUTER="2001:db8::20"
SRV_INNER="fd00:9::1"
PORT=4747
PSK="testkey-testkey-testkey-testkey-32"

workdir="$(mktemp -d)"
cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  [[ -n "${CLI_PID:-}" ]] && kill "$CLI_PID" 2>/dev/null || true
  [[ -n "${HOLDER:-}" ]] && kill "$HOLDER" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

# Client namespace: a holder process in its own netns; we enter it by PID.
setsid unshare --net -- sleep 600 &
HOLDER=$!
CLI_NS="/proc/$HOLDER/ns/net"
for _ in $(seq 1 50); do [[ -e "$CLI_NS" ]] && break; sleep 0.05; done
cns() { nsenter --net="$CLI_NS" "$@"; }

# veth pair: veth-s stays in the server ns, veth-c moves to the client ns.
ip link add veth-s type veth peer name veth-c
ip link set veth-c netns "$HOLDER"

ip addr add "$SRV_OUTER/64" dev veth-s nodad
ip link set veth-s up
ip link set lo up

cns ip addr add "$CLI_OUTER/64" dev veth-c nodad
cns ip link set veth-c up
cns ip link set lo up

cat >"$workdir/up-hook.sh" <<EOF
#!$(command -v bash)
echo "hook-fired iface=\$GREMLIND_IFACE client=\$GREMLIND_CLIENT_ID inner=\$GREMLIND_INNER_PEER" > "$workdir/hook.log"
EOF
chmod +x "$workdir/up-hook.sh"

cat >"$workdir/server.yaml" <<EOF
listen: "[::]:$PORT"
gre_local: "$SRV_OUTER"
inner_pool: "fd00:9::/112"
server_inner: "$SRV_INNER"
mtu: 0
admin_socket: "$workdir/admin.sock"
keepalive_interval: 1s
keepalive_timeout: 3s
auth:
  psk: "$PSK"
hooks:
  up: "$workdir/up-hook.sh"
EOF

cat >"$workdir/client.yaml" <<EOF
keepalive_interval: 1s
keepalive_timeout: 3s
client:
  id: "site-a"
  secret: "$PSK"
EOF

echo "== starting server =="
"$BIN" server -c "$workdir/server.yaml" -v &
SRV_PID=$!

# Wait for the control port to accept connections from the client ns.
for _ in $(seq 1 50); do
  if cns bash -c "exec 3<>/dev/tcp/$SRV_OUTER/$PORT" 2>/dev/null; then break; fi
  sleep 0.1
done

echo "== starting client =="
# Launch via nsenter directly (not the cns function) so $! is the real client
# process and can be signalled for the teardown test below.
nsenter --net="$CLI_NS" "$BIN" connect "[$SRV_OUTER]:$PORT" -c "$workdir/client.yaml" -v &
CLI_PID=$!

# Wait for the client's tunnel interface to appear and come up.
for _ in $(seq 1 50); do
  if cns ip link show grem0 &>/dev/null; then break; fi
  sleep 0.1
done
sleep 0.3

echo "== server-side interface =="
ip -d link show type ip6gre || true
echo "== client-side interface =="
cns ip -d link show grem0 || true

echo "== deterministic link-locals =="
SRV_IF=$(ip -o link show type ip6gre | awk -F': ' '/grem[0-9a-f]/{split($2,a,"@"); print a[1]; exit}')
echo "server $SRV_IF:"; ip -6 addr show dev "$SRV_IF" scope link
echo "client grem0:"; cns ip -6 addr show dev grem0 scope link
if ! ip -6 addr show dev "$SRV_IF" scope link | grep -q "fe80::1/64"; then
  echo "E2E RESULT: FAIL (server link-local != fe80::1)"; exit 1
fi
if ! cns ip -6 addr show dev grem0 scope link | grep -q "fe80::2/64"; then
  echo "E2E RESULT: FAIL (client link-local != fe80::2)"; exit 1
fi
if ip -6 addr show dev "$SRV_IF" scope link | grep -qiE "fe80::[0-9a-f]{2,}"; then
  echo "E2E RESULT: FAIL (unexpected extra/random link-local present)"; exit 1
fi
echo "link-locals OK: server fe80::1, client fe80::2 (no random LL)"

echo "== ping server inner ($SRV_INNER) through the tunnel =="
if ! cns ping -6 -c 3 -W 2 "$SRV_INNER"; then
  echo "E2E RESULT: FAIL (ping)"
  exit 1
fi

echo "== gremlind status =="
"$BIN" status -s "$workdir/admin.sock"
if ! "$BIN" status -s "$workdir/admin.sock" | grep -q "site-a"; then
  echo "E2E RESULT: FAIL (status missing session)"
  exit 1
fi

echo "== up-hook output =="
if [[ -f "$workdir/hook.log" ]]; then
  cat "$workdir/hook.log"
else
  echo "E2E RESULT: FAIL (up hook did not fire)"
  exit 1
fi

echo "== roaming: client outer IP changes ($CLI_OUTER -> 2001:db8::30) =="
CLI_OUTER2="2001:db8::30"
cns ip addr add "$CLI_OUTER2/64" dev veth-c nodad
cns ip addr del "$CLI_OUTER/64" dev veth-c
# The old TCP + GRE break; the dialer must reconnect from the new source IP,
# and the server must re-lease the SAME inner address (fd00:9::2).
roamed=0
for _ in $(seq 1 150); do
  if cns ping -6 -c 1 -W 1 "$SRV_INNER" &>/dev/null; then roamed=1; break; fi
  sleep 0.2
done
if [[ "$roamed" != 1 ]]; then
  echo "E2E RESULT: FAIL (tunnel did not recover after roaming)"
  exit 1
fi
if ! cns ip -6 addr show grem0 | grep -q "fd00:9::2"; then
  echo "E2E RESULT: FAIL (inner IP not preserved across roaming)"
  cns ip -6 addr show grem0
  exit 1
fi
if ! ip -d link show type ip6gre | grep -q "2001:db8::30"; then
  echo "E2E RESULT: FAIL (server did not update GRE remote to new outer IP)"
  exit 1
fi
echo "roaming OK: reconnected from $CLI_OUTER2, inner IP fd00:9::2 preserved"

echo "== verifying server cleanup on client disconnect =="
kill "$CLI_PID" 2>/dev/null || true
CLI_PID=""
for _ in $(seq 1 50); do
  if ! ip link show type ip6gre | grep -q "grem[0-9a-f]"; then break; fi
  sleep 0.1
done
if ip link show type ip6gre | grep -q "grem[0-9a-f]"; then
  echo "E2E RESULT: FAIL (server did not tear down interface)"
  ip -d link show type ip6gre
  exit 1
fi

echo "E2E RESULT: PASS"
