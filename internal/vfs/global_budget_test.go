package vfs

import (
	"strconv"
	"strings"
	"testing"
)

// TestGlobalOverlayBudgetBoundsAllSessions proves overlay memory is bounded across
// sessions, not just within one. maxConns sessions each filling their 8 MiB cap
// would be gigabytes of attacker-held RAM on a small VM; the process-wide ceiling
// must refuse writes once the global total is reached, independent of how many
// sessions are open, and free the bytes back when a session is released.
func TestGlobalOverlayBudgetBoundsAllSessions(t *testing.T) {
	globalOverlayBytes.Store(0)
	defer globalOverlayBytes.Store(0)

	base := testFS(t)
	chunk := []byte(strings.Repeat("A", maxOverlayFileBytes))

	// Open more sessions than the global cap could hold if each filled its own cap,
	// and fill each. The accumulated global total must never exceed the ceiling.
	nSessions := maxGlobalOverlayBytes/maxOverlayBytes + 50
	filesPerSession := maxOverlayBytes / maxOverlayFileBytes
	var sessions []*Session
	for range nSessions {
		sess := base.NewSession("/tmp")
		sessions = append(sessions, sess)
		for i := range filesPerSession {
			_ = sess.WriteFile("/tmp/f"+strconv.Itoa(i), chunk)
		}
	}

	if got := globalOverlayBytes.Load(); got > maxGlobalOverlayBytes {
		t.Fatalf("global overlay total %d exceeded the ceiling %d", got, maxGlobalOverlayBytes)
	}
	// The ceiling must actually have been reached (proving the bound bit, not that
	// the writes were all rejected for another reason).
	if got := globalOverlayBytes.Load(); got < maxGlobalOverlayBytes-maxOverlayBytes {
		t.Fatalf("global total %d suspiciously low; writes may be failing for the wrong reason", got)
	}

	for _, sess := range sessions {
		sess.Release()
	}
	if got := globalOverlayBytes.Load(); got != 0 {
		t.Fatalf("release did not return all bytes: %d still held", got)
	}
}
