// This file is platform-neutral (no build tag): DNS qname parsing runs in
// userspace, never in the verifier (label decompression and validation are not
// verifier-friendly and don't need to be). Kernel-side we only sample raw bytes.
package ebpf

import (
	"errors"
	"strings"
)

const evDNS uint32 = 7 // matches EVENT_DNS in trace.bpf.c

// dnsHeaderLen is the fixed DNS message header (ID, flags, 4 count fields).
const dnsHeaderLen = 12

var errBadDNS = errors.New("malformed DNS query")

// parseDNSQName extracts the first question's QNAME from a DNS query message and
// returns it as a lowercased dotted name. It parses only what a query contains
// (a header + at least one question) and deliberately does NOT follow
// compression pointers: a legitimate *query* question never uses them, so a
// pointer signals a malformed or hostile payload and is rejected. Bounds are
// checked at every step; a label that overruns the sample is an error, never a
// panic or a partial read.
func parseDNSQName(payload []byte) (string, error) {
	if len(payload) < dnsHeaderLen+1 {
		return "", errBadDNS
	}
	pos := dnsHeaderLen
	var labels []string
	for {
		if pos >= len(payload) {
			return "", errBadDNS
		}
		n := int(payload[pos])
		pos++
		if n == 0 { // root label: end of name
			break
		}
		if n&0xc0 != 0 { // compression pointer or reserved bits — reject
			return "", errBadDNS
		}
		if pos+n > len(payload) {
			return "", errBadDNS
		}
		labels = append(labels, string(payload[pos:pos+n]))
		pos += n
	}
	if len(labels) == 0 {
		return "", errBadDNS
	}
	return strings.ToLower(strings.Join(labels, ".")), nil
}
