// Package envelope defines the shared packet wrapper used by the relay and core.
//
// Wire layout (18-byte header, then the payload):
//
//	byte 0       version  (currently 1)
//	byte 1       type     (1 = data, 2 = keepalive)
//	bytes 2..17  sender token (16 random bytes, one per paired endpoint)
//	bytes 18..   payload  (an encrypted WireGuard packet; empty for keepalive)
//
// There is no length field: UDP datagrams and WebSocket messages already carry
// their own length. The relay reads only this header and never decrypts payloads.
package envelope

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// Version is the only format version this code understands.
	Version byte = 1
	// IDSize is the size of a sender token in bytes.
	IDSize = 16
	// HeaderSize is the number of bytes in front of the payload.
	HeaderSize = 2 + IDSize
)

// Type says what a packet is for.
type Type byte

const (
	// TypeData carries an encrypted WireGuard packet.
	TypeData Type = 1
	// TypeKeepalive refreshes the sender's relay address mapping.
	TypeKeepalive Type = 2
)

// SessionID identifies one side of a pairing. Each pairing has two distinct IDs.
type SessionID [IDSize]byte

// Errors returned by Parse and Marshal. Callers drop the packet on any of them.
var (
	ErrTooShort   = errors.New("envelope: shorter than the header")
	ErrBadVersion = errors.New("envelope: unknown version")
	ErrBadType    = errors.New("envelope: unknown type")
	ErrBadPayload = errors.New("envelope: payload does not fit the type")
)

// Packet is a parsed envelope.
type Packet struct {
	Type    Type
	Session SessionID
	Payload []byte
}

// NewSessionID returns a fresh random sender ID.
func NewSessionID() (SessionID, error) {
	var id SessionID
	if _, err := rand.Read(id[:]); err != nil {
		return SessionID{}, fmt.Errorf("envelope: random session id: %w", err)
	}
	return id, nil
}

// validate checks that data has a payload and keepalive does not.
func validate(t Type, payload []byte) error {
	switch t {
	case TypeData:
		if len(payload) == 0 {
			return ErrBadPayload
		}
	case TypeKeepalive:
		if len(payload) != 0 {
			return ErrBadPayload
		}
	default:
		return ErrBadType
	}
	return nil
}

// Marshal appends the encoded packet to dst and returns the extended slice.
// Passing a reused buffer (dst[:0]) avoids an allocation per packet.
func Marshal(dst []byte, p Packet) ([]byte, error) {
	if err := validate(p.Type, p.Payload); err != nil {
		return nil, err
	}
	dst = append(dst, Version, byte(p.Type))
	dst = append(dst, p.Session[:]...)
	return append(dst, p.Payload...), nil
}

// Parse decodes b. The returned Payload points into b and is only valid until
// the caller reuses b.
func Parse(b []byte) (Packet, error) {
	if len(b) < HeaderSize {
		return Packet{}, ErrTooShort
	}
	if b[0] != Version {
		return Packet{}, ErrBadVersion
	}
	p := Packet{Type: Type(b[1]), Payload: b[HeaderSize:]}
	copy(p.Session[:], b[2:HeaderSize])
	if err := validate(p.Type, p.Payload); err != nil {
		return Packet{}, err
	}
	return p, nil
}
