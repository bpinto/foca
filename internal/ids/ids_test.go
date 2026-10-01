package ids

import (
	"testing"
	"time"
)

func TestNewIsSortableAndUnique(t *testing.T) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a := newAt(base)
	b := newAt(base.Add(time.Millisecond))
	if len(a) != 26 || len(b) != 26 {
		t.Fatalf("unexpected lengths %d %d", len(a), len(b))
	}
	if !(a < b) {
		t.Fatalf("ids not time-sortable: %s >= %s", a, b)
	}
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := New()
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

func TestEncodeKnownValue(t *testing.T) {
	var zero [16]byte
	if got := encode(zero); got != "00000000000000000000000000" {
		t.Fatalf("zero encodes to %s", got)
	}
	var max [16]byte
	for i := range max {
		max[i] = 0xff
	}
	if got := encode(max); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("max encodes to %s", got)
	}
}
