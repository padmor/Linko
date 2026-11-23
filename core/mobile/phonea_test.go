package mobile

import (
	"strings"
	"testing"
)

func validInputs() ([]byte, []byte, []byte) {
	privateKey := make([]byte, wireGuardKeySize)
	peerPublicKey := make([]byte, wireGuardKeySize)
	sessionID := make([]byte, sessionIDSize)

	privateKey[0] = 1
	peerPublicKey[0] = 2
	sessionID[0] = 3
	return privateKey, peerPublicKey, sessionID
}

func TestNewPhoneAGatewayRejectsInvalidKeyLength(t *testing.T) {
	privateKey, peerPublicKey, sessionID := validInputs()
	privateKey = privateKey[:wireGuardKeySize-1]

	_, err := NewPhoneAGateway(
		privateKey,
		peerPublicKey,
		sessionID,
		"127.0.0.1:51820",
		"10.77.0.1",
		"10.77.0.2",
		1280,
	)
	if err == nil || !strings.Contains(err.Error(), "private key must be 32 bytes") {
		t.Fatalf("expected private key length error, got %v", err)
	}
}

func TestNewPhoneAGatewayRejectsInvalidSessionLength(t *testing.T) {
	privateKey, peerPublicKey, sessionID := validInputs()
	sessionID = sessionID[:sessionIDSize-1]

	_, err := NewPhoneAGateway(
		privateKey,
		peerPublicKey,
		sessionID,
		"127.0.0.1:51820",
		"10.77.0.1",
		"10.77.0.2",
		1280,
	)
	if err == nil || !strings.Contains(err.Error(), "session ID must be 16 bytes") {
		t.Fatalf("expected session ID length error, got %v", err)
	}
}

func TestNewPhoneAGatewayRejectsInvalidTunnelAddress(t *testing.T) {
	privateKey, peerPublicKey, sessionID := validInputs()

	_, err := NewPhoneAGateway(
		privateKey,
		peerPublicKey,
		sessionID,
		"127.0.0.1:51820",
		"not-an-ip",
		"10.77.0.2",
		1280,
	)
	if err == nil || !strings.Contains(err.Error(), "local tunnel address must be a valid IPv4 address") {
		t.Fatalf("expected local address error, got %v", err)
	}
}

func TestPhoneAGatewayCloseIsSafeWhenEmpty(t *testing.T) {
	gateway := &PhoneAGateway{}
	gateway.Close()
	gateway.Close()
}
