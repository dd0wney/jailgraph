// This file is platform-neutral (no build tag) so the connect-decode logic is
// unit-testable without a kernel; the kernel-touching map drain lives in
// collector_linux.go, mirroring fold.go vs collector_linux.go.
package ebpf

import (
	"net/netip"
	"strconv"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// Address family + protocol constants, matching the values read from the kernel
// sockaddr (uapi #defines, stable across arches).
const (
	afInet     uint32 = 2  // AF_INET
	afInet6    uint32 = 10 // AF_INET6
	ipProtoTCP uint32 = 6  // IPPROTO_TCP
	ipProtoUDP uint32 = 17 // IPPROTO_UDP
)

// connKey mirrors `struct conn_key` in trace.bpf.c: the in-kernel fold key for a
// distinct (process, destination) egress connection. Addr holds a v4 address in
// its first 4 bytes (rest zero) or a full v6 address. Unlike the generated
// traceConnKey (read directly off the kernel map), this neutral struct is never
// read from raw kernel bytes, so it carries no explicit padding.
type connKey struct {
	TGID   uint32
	Family uint32
	Port   uint16
	Addr   [16]byte
}

// connStat mirrors `struct conn_stat` in trace.bpf.c: the folded attempt count
// and socket protocol for one (process, destination).
type connStat struct {
	Count uint64
	Proto uint32
}

// decodeIP renders a destination address as text. AF_INET reads the first 4
// bytes; AF_INET6 reads all 16. netip gives canonical RFC 5952 v6 formatting.
func decodeIP(family uint32, addr [16]byte) string {
	switch family {
	case afInet:
		return netip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]}).String()
	case afInet6:
		return netip.AddrFrom16(addr).String()
	default:
		return ""
	}
}

// protoName maps a socket protocol number to a short name, never failing (an
// unknown protocol is rendered by number rather than dropped).
func protoName(p uint32) string {
	switch p {
	case ipProtoTCP:
		return "tcp"
	case ipProtoUDP:
		return "udp"
	default:
		return "proto-" + strconv.Itoa(int(p))
	}
}

// connToBehavior converts one folded connect record into a decoded BehaviorEvent.
func connToBehavior(k connKey, s connStat) collector.BehaviorEvent {
	return collector.BehaviorEvent{
		Kind:      collector.EventConnect,
		PID:       int32(k.TGID),
		DstIP:     decodeIP(k.Family, k.Addr),
		DstPort:   k.Port,
		Proto:     protoName(s.Proto),
		ConnCount: int64(s.Count),
	}
}

// ntohs converts a network-byte-order 16-bit value (as read raw from the kernel
// sockaddr) to host order. The kernel stores the port big-endian regardless of
// host endianness.
//
// This assumes a little-endian (bpfel) eBPF target — correct today, since
// that's the only target this collector builds for — but the byte-swap here
// is unconditional, so a future bpfeb (big-endian) target would need this
// reviewed (the raw value may already arrive in host order there).
func ntohs(be uint16) uint16 {
	return be<<8 | be>>8
}
