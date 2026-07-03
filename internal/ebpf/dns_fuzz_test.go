package ebpf

import "testing"

// FuzzParseDNSQName asserts the parser never panics on arbitrary input — the
// hard requirement for parsing attacker-influenced payloads off the wire.
func FuzzParseDNSQName(f *testing.F) {
	f.Add(dnsQuery("example", "com"))
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDNSQName(data) // must not panic
	})
}
