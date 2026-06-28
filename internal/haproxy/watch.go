package haproxy

import "time"

// Watcher decides which sources to report as flooding. A source is reported when
// its new-connection rate reaches the threshold and it has not been reported
// within the cooldown, so a sustained flood produces a periodic event rather than
// one per poll. The zero value is not usable; build one with NewWatcher.
type Watcher struct {
	threshold int
	cooldown  time.Duration
	last      map[string]time.Time
}

// NewWatcher returns a Watcher for the given new-connection-rate threshold and
// per-source report cooldown.
func NewWatcher(threshold int, cooldown time.Duration) *Watcher {
	return &Watcher{threshold: threshold, cooldown: cooldown, last: map[string]time.Time{}}
}

// Flooding returns the sources at or over the threshold that are due to be
// reported as of now, recording each so it is not reported again until its
// cooldown elapses. Sources that have dropped back under the threshold are
// forgotten, so a later flood from the same address reports immediately instead
// of waiting out a stale cooldown.
func (w *Watcher) Flooding(srcs []Source, now time.Time) []Source {
	over := make(map[string]bool, len(srcs))
	var due []Source
	for _, s := range srcs {
		if s.ConnRate < w.threshold {
			continue
		}
		over[s.IP] = true
		if t, seen := w.last[s.IP]; seen && now.Sub(t) < w.cooldown {
			continue
		}
		w.last[s.IP] = now
		due = append(due, s)
	}
	for ip := range w.last {
		if !over[ip] {
			delete(w.last, ip)
		}
	}
	return due
}
