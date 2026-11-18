// Package session tracks which two phones belong together and where each of
// them currently is.
//
// A pairing has two tokens, one per side. A packet carries its sender's token,
// so the relay tells the sides apart by token and not by address. That is what
// lets a phone roam (Wi-Fi to mobile data): its address changes, its token
// does not.
package session

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/padmor/linko/protocol/envelope"
)

// Errors returned by Add.
var (
	ErrSameToken = errors.New("session: both sides need different tokens")
	ErrExists    = errors.New("session: token already in use")
)

// side is one phone in a pairing.
type side struct {
	token    envelope.SessionID
	addr     netip.AddrPort // zero until the phone sends its first packet
	lastSeen time.Time
}

// pairing links two sides. Index 0 and 1 are interchangeable.
type pairing struct {
	sides [2]side
}

// ref points at one side of one pairing.
type ref struct {
	p *pairing
	i int
}

// Table is the relay's session state. It is safe for concurrent use.
type Table struct {
	mu          sync.Mutex
	byToken     map[envelope.SessionID]ref
	idleTimeout time.Duration
	now         func() time.Time // replaced in tests
}

// NewTable makes an empty table. A side that stays silent for idleTimeout
// stops receiving forwarded packets.
func NewTable(idleTimeout time.Duration) *Table {
	return &Table{
		byToken:     make(map[envelope.SessionID]ref),
		idleTimeout: idleTimeout,
		now:         time.Now,
	}
}

// Add registers a new pairing with one token per side.
func (t *Table) Add(a, b envelope.SessionID) error {
	if a == b {
		return ErrSameToken
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.byToken[a]; ok {
		return ErrExists
	}
	if _, ok := t.byToken[b]; ok {
		return ErrExists
	}
	p := &pairing{sides: [2]side{{token: a}, {token: b}}}
	t.byToken[a] = ref{p, 0}
	t.byToken[b] = ref{p, 1}
	return nil
}

// Remove ends the pairing that token belongs to. It reports whether one existed.
func (t *Table) Remove(token envelope.SessionID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, ok := t.byToken[token]
	if !ok {
		return false
	}
	delete(t.byToken, r.p.sides[0].token)
	delete(t.byToken, r.p.sides[1].token)
	return true
}

// Route handles one packet that arrived from the address from. It records the
// sender's location and returns where to forward the packet, if anywhere.
//
// It returns false for unknown tokens, for keepalives (they only refresh the
// sender's address), and when the partner is unknown or has gone quiet.
func (t *Table) Route(p envelope.Packet, from netip.AddrPort) (netip.AddrPort, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, ok := t.byToken[p.Session]
	if !ok {
		return netip.AddrPort{}, false
	}
	now := t.now()
	sender := &r.p.sides[r.i]
	sender.addr = from
	sender.lastSeen = now

	if p.Type == envelope.TypeKeepalive {
		return netip.AddrPort{}, false
	}

	partner := &r.p.sides[1-r.i]
	if !partner.addr.IsValid() || now.Sub(partner.lastSeen) > t.idleTimeout {
		return netip.AddrPort{}, false
	}
	return partner.addr, true
}

// Expire forgets the address of every side that has been silent too long and
// returns how many it cleared. The pairings themselves stay until Remove.
// Route already ignores stale partners, so this only frees memory held in
// addresses and keeps the state honest; call it from a timer.
func (t *Table) Expire() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	cleared := 0
	for _, r := range t.byToken {
		s := &r.p.sides[r.i]
		if s.addr.IsValid() && now.Sub(s.lastSeen) > t.idleTimeout {
			s.addr = netip.AddrPort{}
			cleared++
		}
	}
	return cleared
}
