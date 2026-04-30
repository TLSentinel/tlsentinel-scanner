package main

import "testing"

// TestClampConcurrency documents the binary-side concurrency cap behaviour.
// The cap exists so a misconfigured or compromised server cannot push the
// scanner past what its host can handle (FD/goroutine exhaustion).
//
// Two non-obvious cases are pinned here:
//   - A non-positive server value is passed through unchanged, not coerced
//     to the cap. runScanCycle owns the "missing config" default; the cap
//     only pulls absurd values *down*.
//   - A server value equal to the cap is preserved, not bumped.
func TestClampConcurrency(t *testing.T) {
	cases := []struct {
		name    string
		server  int
		ceiling int
		want    int
	}{
		{"under cap returns server value", 30, 64, 30},
		{"at cap returns server value", 64, 64, 64},
		{"over cap returns cap", 200, 64, 64},
		{"zero passes through (runScanCycle applies default)", 0, 64, 0},
		{"negative passes through (runScanCycle applies default)", -1, 64, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampConcurrency(tc.server, tc.ceiling); got != tc.want {
				t.Errorf("clampConcurrency(%d, %d) = %d, want %d",
					tc.server, tc.ceiling, got, tc.want)
			}
		})
	}
}
