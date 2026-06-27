// Package util holds small, dependency-free helpers shared across the honeypot:
// line trimming, URL/host extraction, randomized delays, hex dumps, base58
// generation, and display sanitization. Nothing here imports any other internal
// package, so every package can depend on it without creating a cycle.
package util

import (
	crand "crypto/rand"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"strings"
	"time"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// TrimCRLF removes trailing line terminators. It also strips a trailing NUL,
// which real telnet clients send as the second half of a CR-NUL line ending.
func TrimCRLF(s string) string {
	return strings.TrimRight(s, "\r\n\x00")
}

func SliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ExtractURL returns the first http(s)/ftp argument found, if any.
func ExtractURL(parts []string) string {
	for _, p := range parts {
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") || strings.HasPrefix(p, "ftp://") {
			return p
		}
	}
	return ""
}

// ExtractHost strips scheme, userinfo, and path from a URL, leaving host[:port].
func ExtractHost(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// RandomDelay returns a duration uniformly in [minMs, maxMs] milliseconds.
func RandomDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	return time.Duration(minMs+mrand.IntN(maxMs-minMs)) * time.Millisecond
}

func TimeFromNow(d time.Duration) time.Time {
	return time.Now().Add(d)
}

// HexDump returns the first up-to-32 bytes as space-separated hex.
func HexDump(b []byte) string {
	n := len(b)
	if n > 32 {
		n = 32
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = fmt.Sprintf("%02x", b[i])
	}
	return strings.Join(parts, " ")
}

// base58Unbiased is the largest multiple of 58 that fits in a byte; random bytes at
// or above it are rejected so the mapping to the 58-char alphabet is uniform rather
// than favouring the first 256%58 letters.
const base58Unbiased = 256 - (256 % 58)

// Base58GenStrict is the fail-closed generator for secret tokens: it draws from
// crypto/rand with rejection sampling (no modulo bias) and returns an error rather
// than ever substituting a non-cryptographic source. A portal token must be
// unguessable or not exist at all.
func Base58GenStrict(length int) (string, error) {
	out := make([]byte, length)
	buf := make([]byte, length)
	got := 0
	for got < length {
		if _, err := crand.Read(buf); err != nil {
			return "", err
		}
		for _, x := range buf {
			if int(x) >= base58Unbiased {
				continue // reject to avoid modulo bias
			}
			out[got] = base58Alphabet[int(x)%58]
			got++
			if got == length {
				break
			}
		}
	}
	return string(out), nil
}

// Base58Gen returns a cryptographically random base58 string of the given length,
// for non-secret identifiers (session and recording ids). It uses the unbiased
// strict generator, and only if crypto/rand itself fails (a host without a working
// CSPRNG) does it degrade to a non-cryptographic source rather than crash, so a
// running honeypot keeps minting ids and logging. Secret tokens use Base58GenStrict.
func Base58Gen(length int) string {
	if s, err := Base58GenStrict(length); err == nil {
		return s
	}
	b := make([]byte, length)
	for i := range b {
		b[i] = base58Alphabet[mrand.IntN(58)]
	}
	return string(b)
}

// HostOnly returns the host portion of an "ip:port" address, or the input
// unchanged if it has no port.
func HostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// isTerminalControl reports whether r is a byte that can drive an operator's
// terminal or forge a log line: the C0 controls (below 0x20), DEL (0x7f), and the
// C1 controls (0x80-0x9f, which include the 8-bit CSI 0x9b an attacker can deliver
// as the two UTF-8 bytes 0xC2 0x9B). json.Marshal escapes C0 but passes DEL and C1
// through verbatim, so a captured username or command could otherwise move the
// cursor or clear the screen of anyone viewing the raw log.
func isTerminalControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// SanitizeDisplay makes a captured string safe to print to the operator's
// terminal: tabs become spaces and other control bytes (C0, DEL, C1) become dots.
// The raw bytes are still preserved verbatim in the JSON log (json.Marshal escapes
// them so they cannot forge a line); only this stdout/console view is cleaned, and
// it now also neutralizes DEL and the C1 range an 8-bit terminal would act on.
func SanitizeDisplay(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case isTerminalControl(r):
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
