// This file is platform-neutral (no build tag): the connect-decode logic is
// unit-tested without a kernel, mirroring fold_test.go / entropy_test.go.
package ebpf

import (
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
)

func TestDecodeIP(t *testing.T) {
	tests := []struct {
		name   string
		family uint32
		addr   [16]byte
		want   string
	}{
		{"ipv4 loopback", afInet, [16]byte{127, 0, 0, 1}, "127.0.0.1"},
		{"ipv4 public", afInet, [16]byte{93, 184, 216, 34}, "93.184.216.34"},
		{"ipv6 loopback", afInet6, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1"},
		{"ipv6 full", afInet6, [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeIP(tt.family, tt.addr); got != tt.want {
				t.Errorf("decodeIP(%d, %v) = %q, want %q", tt.family, tt.addr, got, tt.want)
			}
		})
	}
}

func TestConnToBehavior(t *testing.T) {
	k := connKey{TGID: 4242, Family: afInet, Port: 443, Addr: [16]byte{93, 184, 216, 34}}
	s := connStat{Count: 7, Proto: ipProtoTCP}
	be := connToBehavior(k, s)
	if be.Kind != collector.EventConnect {
		t.Fatalf("Kind = %v, want EventConnect", be.Kind)
	}
	if be.PID != 4242 {
		t.Errorf("PID = %d, want 4242", be.PID)
	}
	if be.DstIP != "93.184.216.34" || be.DstPort != 443 {
		t.Errorf("dst = %s:%d, want 93.184.216.34:443", be.DstIP, be.DstPort)
	}
	if be.Proto != "tcp" {
		t.Errorf("Proto = %q, want tcp", be.Proto)
	}
	if be.ConnCount != 7 {
		t.Errorf("ConnCount = %d, want 7", be.ConnCount)
	}
}

func TestNtohs(t *testing.T) {
	// Port 443 in network order is the bytes {0x01, 0xBB} (big-endian, high byte
	// first). Read raw as a native uint16 on a little-endian host, that byte pair
	// is 0xBB01; ntohs must swap it back to 0x01BB (== 443, host order).
	if got := ntohs(0xBB01); got != 443 {
		t.Errorf("ntohs(0xBB01) = %d, want 443", got)
	}
}
