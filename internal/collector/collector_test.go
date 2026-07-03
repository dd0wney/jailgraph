package collector

import "testing"

func TestEventConnectString(t *testing.T) {
	if got := EventConnect.String(); got != "connect" {
		t.Errorf("EventConnect.String() = %q, want %q", got, "connect")
	}
}

func TestEventDNSString(t *testing.T) {
	if got := EventDNS.String(); got != "dns" {
		t.Errorf("EventDNS.String() = %q, want %q", got, "dns")
	}
}
