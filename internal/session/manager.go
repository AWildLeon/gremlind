// Package session ties the control channel to the GRE data-plane: it allocates
// inner addresses, negotiates the tunnel MTU, provisions GRE interfaces, and
// keeps a registry of live sessions for teardown and status reporting.
package session

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
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
	mtuCap      int // hard upper bound from config; 0 = none
	upHook      string
	downHook    string

	keyCounter atomic.Uint32

	mu       sync.Mutex
	sessions map[uint32]*Entry  // active sessions keyed by GRE key
	active   map[string]uint32  // client ID -> its current session key
	leases   map[string]netip.Addr // client ID -> last inner address (sticky)
}

// Config parameterizes the manager.
type Config struct {
	Log         *slog.Logger
	Pool        *ippool.Pool
	ServerInner netip.Addr
	GRELocal    netip.Addr
	OuterMTU    int    // server's outer link MTU (0 = auto-detect)
	MTUCap      int    // config.MTU
	UpHook      string // script run when a session interface comes up
	DownHook    string // script run when a session interface goes down
}

// New builds a Manager using the real netlink data-plane.
func New(cfg Config) *Manager {
	return newWith(cfg, netlinkProvisioner{})
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
		upHook:      cfg.UpHook,
		downHook:    cfg.DownHook,
		sessions:    make(map[uint32]*Entry),
		active:      make(map[string]uint32),
		leases:      make(map[string]netip.Addr),
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
	key := m.nextKey()
	ifName := fmt.Sprintf("grem%x", key)

	// Under the lock: evict any stale session for the same client (roaming —
	// the client reconnected, likely from a new outer IP), then assign the inner
	// address, preferring the client's sticky lease so it keeps the same IP.
	m.mu.Lock()
	evicted := m.evictLocked(p.ClientID)
	clientInner, err := m.allocInnerLocked(p.ClientID, p.RequestedInner)
	if err != nil {
		m.mu.Unlock()
		return control.SessionGrant{}, control.ResultNoAddresses, err
	}
	entry := &Entry{
		ClientID:    p.ClientID,
		IfName:      ifName,
		ClientInner: clientInner,
		ClientOuter: p.ClientOuter,
		GREKey:      key,
		MTU:         mtu,
		Since:       time.Now(),
	}
	m.sessions[key] = entry
	m.active[p.ClientID] = key
	m.leases[p.ClientID] = clientInner
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
		Key:        key,
		MTU:        mtu,
		InnerLocal: m.serverInner,
		InnerPeer:  clientInner,
		LinkLocal:  gre.ServerLinkLocal,
	}); err != nil {
		m.mu.Lock()
		if m.sessions[key] == entry {
			delete(m.sessions, key)
			if m.active[p.ClientID] == key {
				delete(m.active, p.ClientID)
			}
			m.pool.Release(clientInner)
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
		GREKey:     key,
		MTU:        mtu,
	})

	return control.SessionGrant{
		ClientInner: clientInner,
		ServerInner: m.serverInner,
		ServerOuter: m.greLocal,
		GREKey:      key,
		MTU:         uint16(mtu),
	}, control.ResultOK, nil
}

// Teardown implements control.Establisher. It is idempotent and keyed on the
// GRE key: if the session was already superseded by a roaming reconnect, the
// stale connection's teardown finds no entry and does nothing — crucially, it
// must not release the inner address the new session now owns.
func (m *Manager) Teardown(_ control.SessionParams, g control.SessionGrant) {
	m.mu.Lock()
	entry := m.sessions[g.GREKey]
	if entry == nil {
		m.mu.Unlock()
		return // already torn down or evicted by a newer session
	}
	delete(m.sessions, g.GREKey)
	if m.active[entry.ClientID] == g.GREKey {
		delete(m.active, entry.ClientID)
	}
	m.pool.Release(entry.ClientInner) // lease is kept for sticky reconnect
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
// overhead, further clamped by the optional config cap.
func (m *Manager) negotiateMTU(clientOuterMTU int) int {
	outer := m.outerMTU
	if clientOuterMTU > 0 && clientOuterMTU < outer {
		outer = clientOuterMTU
	}
	mtu := outer - gre.Overhead(m.greLocal)
	if m.mtuCap > 0 && m.mtuCap < mtu {
		mtu = m.mtuCap
	}
	if mtu < 1280 && m.greLocal.Is6() {
		mtu = 1280 // IPv6 minimum link MTU
	}
	return mtu
}

// allocInnerLocked assigns an inner address, preferring stability: an explicit
// client request first, then the client's sticky lease (its previous address),
// and finally a fresh address. Caller must hold m.mu. AllocateSpecific/Allocate
// mutate only the pool's own state, which is independently locked.
func (m *Manager) allocInnerLocked(clientID string, requested netip.Addr) (netip.Addr, error) {
	for _, cand := range []netip.Addr{requested, m.leases[clientID]} {
		if cand.IsValid() {
			if err := m.pool.AllocateSpecific(cand); err == nil {
				return cand, nil
			}
		}
	}
	return m.pool.Allocate()
}

// nextKey returns a fresh non-zero GRE key.
func (m *Manager) nextKey() uint32 {
	for {
		k := m.keyCounter.Add(1)
		if k != 0 {
			return k
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
