// Package crosscheck holds cross-service coherence tests. A scan platform
// (Shodan/Censys) shows every banner an IP exposes together and correlates them,
// so the proof that matters is not that any one service looks right but that all of
// them tell one host's story. It lives outside internal/proto (it is not a
// protocol handler) so the safety enumeration guard scans only real handlers.
package crosscheck
