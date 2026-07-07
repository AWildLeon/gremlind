// Package ippool assigns inner tunnel addresses from a configured prefix. It is
// address-family agnostic (IPv6 default, IPv4 supported).
package ippool

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ErrExhausted is returned when no free address remains in the pool.
var ErrExhausted = errors.New("ippool: address pool exhausted")

// Pool hands out unique addresses from a prefix, skipping reserved ones.
type Pool struct {
	mu       sync.Mutex
	prefix   netip.Prefix
	reserved map[netip.Addr]bool
	used     map[netip.Addr]bool
}

// New creates a pool over prefix. The given reserved addresses (e.g. the
// server's own inner address) are never handed out.
func New(prefix netip.Prefix, reserved ...netip.Addr) (*Pool, error) {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return nil, fmt.Errorf("ippool: invalid prefix")
	}
	p := &Pool{
		prefix:   prefix,
		reserved: make(map[netip.Addr]bool),
		used:     make(map[netip.Addr]bool),
	}
	for _, r := range reserved {
		if r.IsValid() {
			p.reserved[r] = true
		}
	}
	return p, nil
}

// Allocate returns the next free address.
func (p *Pool) Allocate() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Start at the first usable host (skip the network address itself).
	for a := p.prefix.Addr().Next(); p.prefix.Contains(a); a = a.Next() {
		if p.reserved[a] || p.used[a] {
			continue
		}
		p.used[a] = true
		return a, nil
	}
	return netip.Addr{}, ErrExhausted
}

// AllocateSpecific reserves a caller-requested address if it is in-range and free.
func (p *Pool) AllocateSpecific(a netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.prefix.Contains(a) {
		return fmt.Errorf("ippool: %s is outside pool %s", a, p.prefix)
	}
	if p.reserved[a] || p.used[a] {
		return fmt.Errorf("ippool: %s is unavailable", a)
	}
	p.used[a] = true
	return nil
}

// Release returns an address to the pool.
func (p *Pool) Release(a netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, a)
}

// InUse reports the number of currently allocated addresses.
func (p *Pool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.used)
}
