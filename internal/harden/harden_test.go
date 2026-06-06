package harden

import "testing"

func TestSeverityRankOrder(t *testing.T) {
	order := []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}
	for i := 0; i+1 < len(order); i++ {
		if order[i].rank() <= order[i+1].rank() {
			t.Errorf("%s.rank()=%d should be > %s.rank()=%d",
				order[i], order[i].rank(), order[i+1], order[i+1].rank())
		}
	}
	if SevInfo.rank() != 0 {
		t.Errorf("Info rank = %d, want 0", SevInfo.rank())
	}
}
