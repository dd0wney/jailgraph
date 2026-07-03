package collector

import "testing"

func TestEventConnectString(t *testing.T) {
	if got := EventConnect.String(); got != "connect" {
		t.Errorf("EventConnect.String() = %q, want %q", got, "connect")
	}
}
