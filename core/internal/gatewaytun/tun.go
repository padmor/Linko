// Package gatewaytun is a userspace TUN device backed by a gVisor network stack.
//
// It is the Phone A side of the tunnel: WireGuard writes decrypted IP packets
// into it, and the gVisor stack hands them to the forwarders in package gateway.
//
// WireGuard's own netstack package hides its gVisor stack, and the gateway
// needs that stack to install forwarders. This file is a trimmed adaptation of
// golang.zx2c4.com/wireguard/tun/netstack (MIT, Copyright (C) 2017-2025
// WireGuard LLC) that exposes the stack and drops what a gateway does not need
// (client dialing, DNS client).
package gatewaytun

import (
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// NICID is the only network interface in the stack.
const NICID tcpip.NICID = 1

// queueLen is how many outbound packets the link endpoint can hold.
const queueLen = 1024

type device struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
}

// New creates the TUN device and its stack. localAddr is the gateway's own
// address inside the tunnel (for example 10.77.0.1).
func New(localAddr netip.Addr, mtu int) (tun.Device, *stack.Stack, error) {
	if !localAddr.Is4() {
		return nil, nil, fmt.Errorf("gatewaytun: only IPv4 is supported for now, got %v", localAddr)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		// Must stay false. With promiscuous mode on, gVisor treats every source
		// address as "one of our own" when HandleLocal is true and drops all
		// client packets as spoofed.
		HandleLocal: false,
	})

	d := &device{
		ep:             channel.New(queueLen, uint32(mtu), ""),
		stack:          s,
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}

	// TCP SACK is off by default in gVisor. Without it a lost packet stalls the
	// whole window, which hurts exactly the lossy mobile links we target.
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, nil, fmt.Errorf("gatewaytun: enable TCP SACK: %v", err)
	}

	d.notifyHandle = d.ep.AddNotify(d)
	if err := s.CreateNIC(NICID, d.ep); err != nil {
		return nil, nil, fmt.Errorf("gatewaytun: create NIC: %v", err)
	}

	addr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(localAddr.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(NICID, addr, stack.AddressProperties{}); err != nil {
		return nil, nil, fmt.Errorf("gatewaytun: add address %v: %v", localAddr, err)
	}

	// Everything not local goes back out through the tunnel.
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: NICID})

	d.events <- tun.EventUp
	return d, s, nil
}

func (d *device) Name() (string, error)    { return "linko-gateway", nil }
func (d *device) File() *os.File           { return nil }
func (d *device) Events() <-chan tun.Event { return d.events }
func (d *device) MTU() (int, error)        { return d.mtu, nil }
func (d *device) BatchSize() int           { return 1 }

// Read hands WireGuard the next packet the stack wants to send to the client.
func (d *device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-d.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write injects packets decrypted by WireGuard into the stack.
func (d *device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkt)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

// WriteNotify is called by the link endpoint when the stack queued a packet.
func (d *device) WriteNotify() {
	pkt := d.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	d.incomingPacket <- view
}

func (d *device) Close() error {
	d.stack.RemoveNIC(NICID)
	d.stack.Close()
	d.ep.RemoveNotify(d.notifyHandle)
	d.ep.Close()
	close(d.events)
	close(d.incomingPacket)
	return nil
}
