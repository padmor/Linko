// Package envelope defines the wrapper around every packet that crosses the relay.
//
// Wire layout (18-byte header, then the payload):
//
//	byte 0       version  (currently 1)
//	byte 1       type     (1 = data, 2 = keepalive)
//	bytes 2..17  session ID (16 random bytes issued at pairing)
//	bytes 18..   payload  (an encrypted WireGuard packet; empty for keepalive)
//
// There is no length field: a UDP datagram or a WebSocket message already
// carries its own length, and a second one could only disagree with it.
//
// The relay never has the keys, so the payload is opaque to it.
package envelope

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// Version is the only format version this code understands.
	Version byte = 1
	// IDSize is the size of a session ID in bytes.
	IDSize = 16
	// HeaderSize is the number of bytes in front of the payload.
	HeaderSize = 2 + IDSize
)

// Type says what a packet is for.
type Type byte

const (
	// TypeData carries an encrypted WireGuard packet.
	TypeData Type = 1
	// TypeKeepalive only keeps the relay's address mapping fresh.
	TypeKeepalive Type = 2
)

// SessionID identifies a pairing. Knowing it is what lets a packet in, so it
// is random, 128 bits, and never logged.
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

// NewSessionID returns a fresh random session ID.
func NewSessionID() (SessionID, error) {
	var id SessionID
	if _, err := rand.Read(id[:]); err != nil {
		return SessionID{}, fmt.Errorf("envelope: random session id: %w", err)
	}
	return id, nil
}

// validate checks that the type and payload agree: data needs a payload,
// keepalive must not have one.
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

// Parse decodes b. The returned Payload points into b and is not copied, so
// it is only valid until the caller reuses b.
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
