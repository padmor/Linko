package envelope

import (
	"bytes"
	"errors"
	"testing"
)

func testID(t *testing.T) SessionID {
	t.Helper()
	id, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRoundTrip(t *testing.T) {
	id := testID(t)
	tests := []struct {
		name string
		in   Packet
	}{
		{"data", Packet{TypeData, id, []byte("encrypted wireguard bytes")}},
		{"keepalive", Packet{TypeKeepalive, id, nil}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := Marshal(nil, tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if len(wire) != HeaderSize+len(tc.in.Payload) {
				t.Fatalf("wire length %d, want %d", len(wire), HeaderSize+len(tc.in.Payload))
			}
			got, err := Parse(wire)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.Type != tc.in.Type || got.Session != tc.in.Session || !bytes.Equal(got.Payload, tc.in.Payload) {
				t.Fatalf("got %+v, want %+v", got, tc.in)
			}
		})
	}
}

// The header size must match the MTU math in the roadmap (1500-40-8-18-32).
func TestHeaderSize(t *testing.T) {
	if HeaderSize != 18 {
		t.Fatalf("HeaderSize = %d, the MTU math assumes 18", HeaderSize)
	}
}

func TestParseRejects(t *testing.T) {
	id := testID(t)
	good, _ := Marshal(nil, Packet{TypeData, id, []byte("x")})

	withByte := func(i int, v byte) []byte {
		b := append([]byte(nil), good...)
		b[i] = v
		return b
	}
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTooShort},
		{"one byte short of header", good[:HeaderSize-1], ErrTooShort},
		{"wrong version", withByte(0, 2), ErrBadVersion},
		{"unknown type", withByte(1, 9), ErrBadType},
		{"type zero", withByte(1, 0), ErrBadType},
		{"data without payload", good[:HeaderSize], ErrBadPayload},
		{"keepalive with payload", withByte(1, byte(TypeKeepalive)), ErrBadPayload},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMarshalRejects(t *testing.T) {
	id := testID(t)
	tests := []struct {
		name string
		in   Packet
		want error
	}{
		{"unknown type", Packet{Type(9), id, []byte("x")}, ErrBadType},
		{"data without payload", Packet{TypeData, id, nil}, ErrBadPayload},
		{"keepalive with payload", Packet{TypeKeepalive, id, []byte("x")}, ErrBadPayload},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Marshal(nil, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// Marshal appends, so a reused buffer must not be disturbed before its length.
func TestMarshalAppends(t *testing.T) {
	id := testID(t)
	prefix := []byte("keep")
	out, err := Marshal(prefix, Packet{TypeKeepalive, id, nil})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("keep")) || len(out) != 4+HeaderSize {
		t.Fatalf("unexpected output %x", out)
	}
}

func TestSessionIDsDiffer(t *testing.T) {
	if testID(t) == testID(t) {
		t.Fatal("two fresh session IDs were equal")
	}
}

// FuzzParse feeds arbitrary bytes: Parse must never panic, and anything it
// accepts must encode back to the same bytes.
func FuzzParse(f *testing.F) {
	id, _ := NewSessionID()
	seed, _ := Marshal(nil, Packet{TypeData, id, []byte("x")})
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		again, err := Marshal(nil, p)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted %x but re-encoded to %x (%v)", b, again, err)
		}
	})
}
