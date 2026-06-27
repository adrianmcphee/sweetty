package shell

import (
	"strings"
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
)

// lineCount returns how many non-empty trailing-newline-trimmed lines out holds.
func lineCount(out string) int {
	out = strings.TrimRight(out, "\n")
	if out == "" {
		return 0
	}
	return len(strings.Split(out, "\n"))
}

// TestHeadTailHonorLineCount pins the count handling for head and tail, including
// the obsolete `-NUM` shorthand (`head -1`) that an attacker reaches for
// constantly. A regression that ignored the count and returned the default ten
// lines would be an immediate coherence tell on the most-run recon commands.
func TestHeadTailHonorLineCount(t *testing.T) {
	p := persona.Generate()
	base, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	sh := &Shell{fs: base.NewSession("/root")}

	// /etc/passwd has well over ten lines, so a broken count is visible.
	full, err := sh.fs.ReadFile(sh.fs.Resolve("/etc/passwd"))
	if err != nil {
		t.Fatalf("reading /etc/passwd failed: %v", err)
	}
	if total := lineCount(string(full)); total <= 10 {
		t.Fatalf("expected /etc/passwd to have >10 lines for this test, got %d", total)
	}

	cases := []struct {
		name string
		args []string
		tail bool
		want int
	}{
		{"head -1", []string{"head", "-1", "/etc/passwd"}, false, 1},
		{"head -3", []string{"head", "-3", "/etc/passwd"}, false, 3},
		{"head -n 2", []string{"head", "-n", "2", "/etc/passwd"}, false, 2},
		{"head -n5", []string{"head", "-n5", "/etc/passwd"}, false, 5},
		{"tail -1", []string{"tail", "-1", "/etc/passwd"}, true, 1},
		{"tail -4", []string{"tail", "-4", "/etc/passwd"}, true, 4},
		{"head default", []string{"head", "/etc/passwd"}, false, 10},
	}
	for _, c := range cases {
		out, code := sh.cmdHeadTail(c.args, "", c.tail)
		if code != 0 {
			t.Errorf("%s: exit %d, out %q", c.name, code, out)
			continue
		}
		if got := lineCount(out); got != c.want {
			t.Errorf("%s returned %d lines, want %d:\n%q", c.name, got, c.want, out)
		}
	}

	// The stdin (pipe) path still honours the count too.
	if out, _ := sh.cmdHeadTail([]string{"head", "-2"}, "a\nb\nc\nd\n", false); strings.TrimRight(out, "\n") != "a\nb" {
		t.Errorf("head -2 over stdin = %q, want \"a\\nb\"", out)
	}

	// Byte mode (-c) emits exactly N bytes from the start (head) or end (tail), with
	// no added newline.
	if out, _ := sh.cmdHeadTail([]string{"head", "-c", "3"}, "abcdefg", false); out != "abc" {
		t.Errorf("head -c 3 = %q, want \"abc\"", out)
	}
	if out, _ := sh.cmdHeadTail([]string{"head", "-c5"}, "abcdefg", false); out != "abcde" {
		t.Errorf("head -c5 = %q, want \"abcde\"", out)
	}
	if out, _ := sh.cmdHeadTail([]string{"tail", "-c", "2"}, "abcdefg", true); out != "fg" {
		t.Errorf("tail -c 2 = %q, want \"fg\"", out)
	}
}
