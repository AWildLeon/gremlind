// Package session ties the control channel to the GRE data-plane: it allocates
// inner addresses, negotiates the tunnel MTU, provisions GRE interfaces, and
// keeps a registry of live sessions for teardown and status reporting.
package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"gremlind/internal/control"
	"gremlind/internal/gre"
	"gremlind/internal/hooks"
	"gremlind/internal/ippool"
)

// Provisioner abstracts the data-plane so the manager is unit-testable without
// netlink/root. The real implementation is gre.Ensure/gre.Remove.
type Provisioner interface {
	Ensure(p gre.Params) error
	Remove(name string) error
}

// netlinkProvisioner is the production data-plane backed by package gre.
type netlinkProvisioner struct{}

func (netlinkProvisioner) Ensure(p gre.Params) error { return gre.Ensure(p) }
func (netlinkProvisioner) Remove(name string) error  { return gre.Remove(name) }

// Entry is a live session in the registry.
type Entry struct {
	ClientID    string     `json:"client_id"`
	IfName      string     `json:"iface"`
	ClientInner netip.Addr `json:"client_inner"`
	ClientOuter netip.Addr `json:"client_outer"`
	GREKey      uint32     `json:"gre_key"`
	MTU         int        `json:"mtu"`
	Since       time.Time  `json:"since"`
}

// Manager provisions sessions and satisfies control.Establisher.
type Manager struct {
	log         *slog.Logger
	pool        *ippool.Pool
	prov        Provisioner
	serverInner netip.Addr
	greLocal    netip.Addr
	outerMTU    int
	mtuCap      int  // hard upper bound from config; 0 = none
	useGREKey   bool // whether to set GRE key fields; false = plain GRE
	useGRESeq   bool // whether to set GRE sequence-number fields
	upHook      string
	downHook    string
	leaseTTL    time.Duration
	fouPort     uint16

	mu         sync.Mutex
	sessions   map[uint32]*Entry     // active sessions keyed by GRE key
	active     map[string]uint32     // client ID -> its current session key
	leases     map[string]netip.Addr // client ID -> last inner address (sticky)
	leaseTimes map[string]time.Time  // last time the sticky lease was refreshed
}

// Config parameterizes the manager.
type Config struct {
	Log         *slog.Logger
	Pool        *ippool.Pool
	ServerInner netip.Addr
	GRELocal    netip.Addr
	OuterMTU    int           // server's outer link MTU (0 = auto-detect)
	MTUCap      int           // config.MTU
	UseGREKey   bool          // true = keyed GRE; false = no GRE key field
	UseGRESeq   bool          // true = GRE sequence-number fields
	UpHook      string        // script run when a session interface comes up
	DownHook    string        // script run when a session interface goes down
	LeaseTTL    time.Duration // sticky lease lifetime after last use; 0 disables expiry
	FOUPort     uint16        // wrap tunnels in Foo-over-UDP on this port; 0 = plain GRE
}

// New builds a Manager using the real netlink data-plane.
func New(cfg Config) *Manager {
	return NewWithProvisioner(cfg, netlinkProvisioner{})
}

// NewWithProvisioner builds a Manager using an alternate data-plane backend,
// e.g. the split-privilege netlink RPC broker.
func NewWithProvisioner(cfg Config, prov Provisioner) *Manager {
	return newWith(cfg, prov)
}

func newWith(cfg Config, prov Provisioner) *Manager {
	outer := cfg.OuterMTU
	if outer == 0 {
		if m, err := gre.OuterMTU(cfg.GRELocal); err == nil {
			outer = m
		} else {
			cfg.Log.Warn("could not detect outer MTU, assuming 1500", "err", err)
			outer = 1500
		}
	}
	return &Manager{
		log:         cfg.Log,
		pool:        cfg.Pool,
		prov:        prov,
		serverInner: cfg.ServerInner,
		greLocal:    cfg.GRELocal,
		outerMTU:    outer,
		mtuCap:      cfg.MTUCap,
		useGREKey:   cfg.UseGREKey,
		useGRESeq:   cfg.UseGRESeq,
		upHook:      cfg.UpHook,
		downHook:    cfg.DownHook,
		leaseTTL:    cfg.LeaseTTL,
		fouPort:     cfg.FOUPort,
		sessions:    make(map[uint32]*Entry),
		active:      make(map[string]uint32),
		leases:      make(map[string]netip.Addr),
		leaseTimes:  make(map[string]time.Time),
	}
}

// Establish implements control.Establisher.
func (m *Manager) Establish(ctx context.Context, p control.SessionParams) (control.SessionGrant, control.Result, error) {
	if !p.ClientOuter.IsValid() {
		return control.SessionGrant{}, control.ResultInternal, fmt.Errorf("missing client outer address")
	}
	if p.ClientOuter.Is6() != m.greLocal.Is6() {
		return control.SessionGrant{}, control.ResultUnsupported,
			fmt.Errorf("outer family mismatch: client %s vs server %s", p.ClientOuter, m.greLocal)
	}

	mtu := m.negotiateMTU(int(p.OuterMTU))

	// Under the lock: evict any stale session for the same client (roaming —
	// the client reconnected, likely from a new outer IP), then assign the inner
	// address, preferring the client's sticky lease so it keeps the same IP.
	m.mu.Lock()
	m.purgeExpiredLeasesLocked(time.Now())
	evicted := m.evictLocked(p.ClientID)
	clientInner, err := m.allocInnerLocked(p.ClientID, p.RequestedInner)
	if err != nil {
		m.mu.Unlock()
		return control.SessionGrant{}, control.ResultNoAddresses, err
	}
	sessionKey, err := m.randomKeyLocked()
	if err != nil {
		m.pool.Release(clientInner)
		m.mu.Unlock()
		return control.SessionGrant{}, control.ResultInternal, err
	}
	greKey := uint32(0)
	if m.useGREKey {
		greKey = sessionKey
	}
	tunnelFlags := uint32(0)
	if m.useGREKey {
		tunnelFlags |= control.TunnelFlagGREKey
	}
	if m.useGRESeq {
		tunnelFlags |= control.TunnelFlagGRESeq
	}
	ifName := m.ifName(sessionKey)
	entry := &Entry{
		ClientID:    p.ClientID,
		IfName:      ifName,
		ClientInner: clientInner,
		ClientOuter: p.ClientOuter,
		GREKey:      greKey,
		MTU:         mtu,
		Since:       time.Now(),
	}
	m.sessions[sessionKey] = entry
	m.active[p.ClientID] = sessionKey
	m.leases[p.ClientID] = clientInner
	m.leaseTimes[p.ClientID] = entry.Since
	m.mu.Unlock()

	// Data-plane and hooks run outside the lock.
	if evicted != nil {
		m.log.Info("evicting stale session (roaming reconnect)",
			"client", p.ClientID, "old_iface", evicted.IfName, "old_outer", evicted.ClientOuter)
		m.removeAndNotify(evicted)
	}

	if err := m.prov.Ensure(gre.Params{
		Name:       ifName,
		Local:      m.greLocal,
		Remote:     p.ClientOuter,
		Key:        greKey,
		Seq:        m.useGRESeq,
		MTU:        mtu,
		InnerLocal: m.serverInner,
		InnerPeer:  clientInner,
		LinkLocal:  gre.ServerLinkLocal,
		FOUSport:   m.fouPort,
		FOUDport:   m.fouPort,
	}); err != nil {
		m.mu.Lock()
		if m.sessions[sessionKey] == entry {
			delete(m.sessions, sessionKey)
			if m.active[p.ClientID] == sessionKey {
				delete(m.active, p.ClientID)
			}
			m.pool.Release(clientInner)
			delete(m.leases, p.ClientID)
			delete(m.leaseTimes, p.ClientID)
		}
		m.mu.Unlock()
		return control.SessionGrant{}, control.ResultInternal, err
	}

	hooks.Run(ctx, m.log, m.upHook, hooks.Info{
		Event:      "up",
		Iface:      ifName,
		ClientID:   p.ClientID,
		InnerLocal: m.serverInner,
		InnerPeer:  clientInner,
		OuterLocal: m.greLocal,
		OuterPeer:  p.ClientOuter,
		GREKey:     greKey,
		MTU:        mtu,
	})

	return control.SessionGrant{
		ClientInner: clientInner,
		ServerInner: m.serverInner,
		ServerOuter: m.greLocal,
		GREKey:      greKey,
		TunnelFlags: tunnelFlags,
		MTU:         uint16(mtu),
		SessionKey:  sessionKey,
	}, control.ResultOK, nil
}

// Teardown implements control.Establisher. It is idempotent and keyed on the
// server-local session key: if the session was already superseded by a roaming
// reconnect, the stale connection's teardown finds no entry and does nothing —
// crucially, it must not release the inner address the new session now owns.
func (m *Manager) Teardown(_ control.SessionParams, g control.SessionGrant) {
	m.mu.Lock()
	entry := m.sessions[g.SessionKey]
	if entry == nil {
		m.mu.Unlock()
		return // already torn down or evicted by a newer session
	}
	delete(m.sessions, g.SessionKey)
	if m.active[entry.ClientID] == g.SessionKey {
		delete(m.active, entry.ClientID)
	}
	m.pool.Release(entry.ClientInner) // lease is kept for sticky reconnect
	m.leaseTimes[entry.ClientID] = time.Now()
	m.mu.Unlock()

	m.removeAndNotify(entry)
}

// evictLocked removes the client's current session from the registry (if any)
// and releases its inner address so it can be re-leased to the reconnecting
// session. It returns the evicted entry so the caller can tear down its
// data-plane outside the lock. Caller must hold m.mu.
func (m *Manager) evictLocked(clientID string) *Entry {
	oldKey, ok := m.active[clientID]
	if !ok {
		return nil
	}
	entry := m.sessions[oldKey]
	delete(m.sessions, oldKey)
	delete(m.active, clientID)
	if entry != nil {
		m.pool.Release(entry.ClientInner)
	}
	return entry
}

// removeAndNotify deletes the interface and runs the down hook for an entry.
func (m *Manager) removeAndNotify(entry *Entry) {
	if err := m.prov.Remove(entry.IfName); err != nil {
		m.log.Warn("interface removal failed", "iface", entry.IfName, "err", err)
	}
	hooks.Run(context.Background(), m.log, m.downHook, hooks.Info{
		Event:      "down",
		Iface:      entry.IfName,
		ClientID:   entry.ClientID,
		InnerLocal: m.serverInner,
		InnerPeer:  entry.ClientInner,
		OuterLocal: m.greLocal,
		OuterPeer:  entry.ClientOuter,
		GREKey:     entry.GREKey,
		MTU:        entry.MTU,
	})
}

// negotiateMTU picks the tunnel MTU: min of both peers' outer MTU minus the GRE
// overhead, further clamped by the optional config cap. It never returns a
// non-positive or wrapped value even if an authenticated peer reports a bogus
// tiny outer MTU.
func (m *Manager) negotiateMTU(clientOuterMTU int) int {
	outer := m.outerMTU
	if clientOuterMTU > 0 && clientOuterMTU < outer {
		outer = clientOuterMTU
	}
	mtu := outer - gre.OverheadWithFOU(m.greLocal, m.useGREKey, m.useGRESeq, m.fouPort != 0)
	if m.mtuCap > 0 && m.mtuCap < mtu {
		mtu = m.mtuCap
	}
	if minMTU := minimumTunnelMTU(m.greLocal); mtu < minMTU {
		mtu = minMTU
	}
	return mtu
}

func minimumTunnelMTU(outer netip.Addr) int {
	if outer.Is6() {
		return 1280 // IPv6 minimum link MTU
	}
	return 576 // IPv4 minimum reassembly MTU; prevents negative/overflow MTUs.
}

// allocInnerLocked assigns an inner address, preferring stability: an explicit
// client request first, then the client's sticky lease (its previous address),
// and finally a fresh address. Sticky leases are treated as reservations while
// they are unexpired: an authenticated client must not be able to request or be
// freshly allocated another client's inactive lease. Caller must hold m.mu.
// AllocateSpecific/Allocate mutate only the pool's own state, which is
// independently locked.
func (m *Manager) allocInnerLocked(clientID string, requested netip.Addr) (netip.Addr, error) {
	for _, cand := range []netip.Addr{requested, m.leases[clientID]} {
		if cand.IsValid() && m.leaseAvailableToLocked(clientID, cand) {
			if err := m.pool.AllocateSpecific(cand); err == nil {
				return cand, nil
			}
		}
	}

	// Pool.Allocate returns the next free address without knowing about sticky
	// leases. Skip addresses reserved for other clients, then put them back before
	// returning so a failed allocation attempt does not consume the pool.
	var skipped []netip.Addr
	for {
		addr, err := m.pool.Allocate()
		if err != nil {
			for _, skippedAddr := range skipped {
				m.pool.Release(skippedAddr)
			}
			return netip.Addr{}, err
		}
		if m.leaseAvailableToLocked(clientID, addr) {
			for _, skippedAddr := range skipped {
				m.pool.Release(skippedAddr)
			}
			return addr, nil
		}
		skipped = append(skipped, addr)
	}
}

// leaseAvailableToLocked reports whether addr is not reserved by another
// client's sticky lease. Caller must hold m.mu.
func (m *Manager) leaseAvailableToLocked(clientID string, addr netip.Addr) bool {
	for owner, leased := range m.leases {
		if owner != clientID && leased == addr {
			return false
		}
	}
	return true
}

func (m *Manager) ifName(key uint32) string {
	if key == 0 {
		return "grem"
	}
	return fmt.Sprintf("grem%x", key)
}

// purgeExpiredLeasesLocked drops inactive sticky leases after the configured
// lifetime. Active sessions are never purged. Caller must hold m.mu.
func (m *Manager) purgeExpiredLeasesLocked(now time.Time) {
	if m.leaseTTL <= 0 {
		return
	}
	for clientID, t := range m.leaseTimes {
		if _, active := m.active[clientID]; active {
			continue
		}
		if now.Sub(t) > m.leaseTTL {
			delete(m.leases, clientID)
			delete(m.leaseTimes, clientID)
		}
	}
}

// randomKeyLocked returns a fresh unpredictable non-zero GRE key. Caller must
// hold m.mu so the active-session collision check is stable.
func (m *Manager) randomKeyLocked() (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("generate GRE key: %w", err)
		}
		k := binary.BigEndian.Uint32(b[:])
		if k != 0 && m.sessions[k] == nil {
			return k, nil
		}
	}
}

// Sessions returns a snapshot of the active session registry.
func (m *Manager) Sessions() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, 0, len(m.sessions))
	for _, e := range m.sessions {
		out = append(out, *e)
	}
	return out
}
