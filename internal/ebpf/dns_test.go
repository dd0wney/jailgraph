package ebpf

import "testing"

// dnsQuery builds a minimal DNS query message: header + one question with the
// given labels, QTYPE=A, QCLASS=IN.
func dnsQuery(labels ...string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0} // header, QDCOUNT=1
	for _, l := range labels {
		msg = append(msg, byte(len(l)))
		msg = append(msg, []byte(l)...)
	}
	msg = append(msg, 0x00)       // root label terminator
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg
}

func TestParseDNSQName(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
		wantErr bool
	}{
		{"example.com", dnsQuery("example", "com"), "example.com", false},
		{"uppercase normalized", dnsQuery("Example", "COM"), "example.com", false},
		{"single label", dnsQuery("localhost"), "localhost", false},
		{"root only", dnsQuery(), "", true},
		{"too short", []byte{0x12, 0x34}, "", true},
		{"empty", nil, "", true},
		{"label overruns buffer", []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x3f, 'a'}, "", true},
		{"compression pointer rejected", append(dnsHeader(), 0xc0, 0x0c), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDNSQName(tt.payload)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseDNSQName = %q, want %q", got, tt.want)
			}
		})
	}
}

func dnsHeader() []byte {
	return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}
