package server

import (
	"strings"
	"testing"
	"time"
)

// The cache counts the encoded size of its reports and starts over past its budget.
func TestCooldownByteBudget(t *testing.T) {
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	c := newCooldown(5*time.Minute, func() time.Time { return clock })
	c.budget = 3000
	report := func(size int) func() (Report, error) {
		return func() (Report, error) { return Report{Target: strings.Repeat("x", size)}, nil }
	}
	c.do("a", false, false, report(1000))
	c.do("b", false, false, report(1000))
	if len(c.entries) != 2 || c.bytes < 2000 || c.bytes > 2600 {
		t.Fatalf("after two: %d entries, %d bytes", len(c.entries), c.bytes)
	}
	clock = clock.Add(2 * time.Minute)
	c.do("a", false, true, report(10))
	if len(c.entries) != 2 || c.bytes > 1600 {
		t.Errorf("overwrite kept the old size: %d entries, %d bytes", len(c.entries), c.bytes)
	}
	c.do("c", false, false, report(2500))
	if len(c.entries) != 1 || c.entries["c"].size == 0 || c.bytes != c.entries["c"].size {
		t.Errorf("past the budget the cache did not start over: %d entries, %d bytes", len(c.entries), c.bytes)
	}
	clock = clock.Add(10 * time.Minute)
	c.do("d", false, false, report(10))
	if _, kept := c.entries["c"]; kept || c.bytes != c.entries["d"].size {
		t.Errorf("the sweep did not return bytes: %d bytes, %d entries", c.bytes, len(c.entries))
	}
}
