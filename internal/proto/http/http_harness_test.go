package http_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	httpproto "sweetty/internal/proto/http"
	"sweetty/internal/testharness"
)

func TestHTTPWordPressPersona(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(httpproto.New(nil, p, "wordpress"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.Send("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.81.0\r\n\r\n")
	resp := h.ReadFor(600 * time.Millisecond)
	if !strings.Contains(resp, "Server:") {
		t.Fatalf("no Server header in response: %q", resp)
	}
	if !strings.Contains(resp, p.WPVer) {
		t.Fatalf("response does not advertise the persona WordPress version %q: %q", p.WPVer, resp)
	}
	e, ok := h.FindEvent("HTTP_REQUEST")
	if !ok {
		t.Fatal("no HTTP_REQUEST event")
	}
	if !strings.Contains(strings.ToLower(e.UserAgent+e.Request), "curl") && !hasUA(h) {
		t.Logf("request: %+v", e)
	}
}

func hasUA(h *testharness.Harness) bool {
	for _, e := range h.Entries() {
		if strings.Contains(strings.ToLower(e.UserAgent), "curl") {
			return true
		}
	}
	return false
}

func TestHTTPPostIsHashed(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(httpproto.New(nil, p, "wordpress"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	body := "log=admin&pwd=hunter2&wp-submit=Log+In"
	h.Send("POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body)

	e, ok := h.WaitEvent("HTTP_POST", 5*time.Second)
	if !ok {
		t.Fatal("no HTTP_POST event")
	}
	if e.SHA256 == "" {
		t.Fatal("HTTP_POST has no sha256 of the body")
	}
	if !strings.Contains(e.Body, "admin") {
		t.Fatalf("posted body not captured: %q", e.Body)
	}
}

// TestPostShaMatchesBody proves the HTTP_POST sha256 is the exact hash of the
// bytes the attacker sent, so an analyst can fingerprint a payload by hash alone.
func TestPostShaMatchesBody(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(httpproto.New(nil, p, "wordpress"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	body := "log=root&pwd=correct-horse-battery-staple&wp-submit=Log+In"
	h.Send("POST /wp-login.php HTTP/1.1\r\nHost: example.com\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body)

	e, ok := h.WaitEvent("HTTP_POST", 5*time.Second)
	if !ok {
		t.Fatal("no HTTP_POST event")
	}
	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])
	if e.SHA256 != want {
		t.Fatalf("HTTP_POST sha256 = %q, want %q", e.SHA256, want)
	}
}
