// Package tunnel sets up WireGuard devices for both ends of the link.
//
// It owns key generation and the small text configuration that wireguard-go
// accepts, so no other package has to know that format.
package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// keepaliveSeconds keeps NAT mappings alive on mobile networks. It must stay
// well under the relay idle timeout (120 s >= 4 x 25 s).
const keepaliveSeconds = 25

// Key is a 32-byte Curve25519 key.
type Key [32]byte

// Hex returns the key as lowercase hex, the format wireguard-go expects.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// NewKeyPair makes a fresh private key and its public key.
func NewKeyPair() (private, public Key, err error) {
	if _, err = rand.Read(private[:]); err != nil {
		return Key{}, Key{}, fmt.Errorf("tunnel: random key: %w", err)
	}
	// Clamp as the Curve25519 spec requires.
	private[0] &= 248
	private[31] = (private[31] & 127) | 64

	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, Key{}, fmt.Errorf("tunnel: derive public key: %w", err)
	}
	copy(public[:], pub)
	return private, public, nil
}

// Peer describes the other end of the tunnel.
type Peer struct {
	PublicKey  Key
	AllowedIPs []string // for example "0.0.0.0/0" or "10.77.0.2/32"
	Endpoint   string   // "ip:port"; empty if we only listen for this peer
	Keepalive  bool     // send keepalives (set on the side behind a NAT)
}

// Config is everything one end needs.
type Config struct {
	PrivateKey Key
	ListenPort int // 0 lets the OS pick; use a fixed port on the listening side
	Peer       Peer
}

// uapi renders the configuration in wireguard-go's text format.
func (c Config) uapi() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.PrivateKey.Hex())
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	fmt.Fprintf(&b, "public_key=%s\n", c.Peer.PublicKey.Hex())
	for _, ip := range c.Peer.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	if c.Peer.Endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", c.Peer.Endpoint)
	}
	if c.Peer.Keepalive {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepaliveSeconds)
	}
	return b.String()
}

// Up starts a WireGuard device on top of tdev with the platform's default Bind.
func Up(tdev tun.Device, cfg Config, name string) (*device.Device, error) {
	return UpWithBind(tdev, cfg, name, conn.NewDefaultBind())
}

// UpWithBind starts a WireGuard device with an injected transport Bind.
// This is used by Linko to route WireGuard packets through its relay.
func UpWithBind(tdev tun.Device, cfg Config, name string, bind conn.Bind) (*device.Device, error) {
	if bind == nil {
		return nil, fmt.Errorf("tunnel: %s has no network bind", name)
	}
	logger := device.NewLogger(device.LogLevelError, name+" ")
	dev := device.NewDevice(tdev, bind, logger)
	if err := dev.IpcSet(cfg.uapi()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: configure %s: %w", name, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: bring up %s: %w", name, err)
	}
	return dev, nil
}
