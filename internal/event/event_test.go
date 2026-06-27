package event

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestLogInjectionIsEscaped proves an attacker cannot forge a second event by
// embedding a newline (or CR, or NUL) in a captured field. The whole entry is
// marshalled as one JSON object per physical line, so control bytes are escaped
// inside the string and a planted "event":"FORGED" never parses as its own line.
func TestLogInjectionIsEscaped(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "ev-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	lg, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	payload := "id\n{\"event\":\"FORGED\",\"ip\":\"6.6.6.6\"}\r\ntail\x00end"
	lg.Log(Entry{Event: "COMMAND", IP: "1.2.3.4", Command: payload})
	lg.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("expected exactly one log line, got %d:\n%s", len(lines), data)
	}

	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("log line is not valid JSON: %v", err)
	}
	if e.Event != "COMMAND" {
		t.Fatalf("event corrupted: %q", e.Event)
	}
	if e.Command != payload {
		t.Fatalf("command not round-tripped verbatim (control bytes lost): %q", e.Command)
	}

	for _, l := range lines {
		var x Entry
		if json.Unmarshal([]byte(l), &x) == nil && x.Event == "FORGED" {
			t.Fatal("a forged event was injected into the log via a captured field")
		}
	}
}

// TestLogStampsTimeAndSensor proves the logger fills the schema fields callers
// rely on for correlation and ordering.
func TestLogStampsTimeAndSensor(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "ev-*.log")
	path := f.Name()
	f.Close()
	lg, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	lg.Log(Entry{Event: "SESSION_START", IP: "1.2.3.4", Session: "abc123"})
	lg.Close()

	data, _ := os.ReadFile(path)
	var e Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &e); err != nil {
		t.Fatal(err)
	}
	if e.Time == "" || e.EpochMs == 0 {
		t.Fatalf("time not stamped: %+v", e)
	}
	if e.Session != "abc123" {
		t.Fatalf("session id lost: %q", e.Session)
	}
}
