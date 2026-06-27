package telnet_test

// The vertical-slice layer. Where coherence_test.go in internal/shell proves the
// generators agree in isolation, this drives ONE complete believable attacker
// session over the real telnet protocol and asserts coherence at every hop of the
// path a curious human actually walks:
//
//   telnet login -> shell prompt -> pwd/cd/ls/cat (VFS-backed, mutually agreeing)
//   -> touch/echo>/mkdir/rm (per-session overlay) -> fake wget (intent logged, no
//   egress, no host byte) -> persona-rendered /etc/* (one identity everywhere).
//
// One end-to-end path proven coherent is worth more than many shallow per-command
// checks: a honeypot is caught by what it contradicts between hops, not by any one
// command in isolation.

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/telnet"
	"sweetty/internal/testharness"
)

// TestVerticalSliceIsCoherentEndToEnd walks the whole slice as a single session and
// checks that each hop agrees with the ones around it.
func TestVerticalSliceIsCoherentEndToEnd(t *testing.T) {
	// A local sink that flags any outbound connection, so the download hop proves
	// the no-egress boundary in-line rather than trusting it.
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	var dialed int32
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			atomic.StoreInt32(&dialed, 1)
			c.Close()
		}
	}()

	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// HOP 1: the prompt is this instance's identity, not a constant.
	out := run(h, "pwd")
	if !strings.Contains(out, "/root") {
		t.Fatalf("login did not land in /root: %q", out)
	}
	if !strings.Contains(out, "root@"+p.Hostname) {
		t.Fatalf("prompt does not carry the persona hostname %q: %q", p.Hostname, out)
	}

	// HOP 2: cd changes directory AND the prompt follows it.
	run(h, "cd /var/log")
	out = run(h, "pwd")
	if !strings.Contains(out, "/var/log") {
		t.Fatalf("cd did not move the cwd: %q", out)
	}
	if !strings.Contains(out, p.Hostname+":/var/log") {
		t.Fatalf("prompt path did not follow cd: %q", out)
	}

	// HOP 3: ls, stat and wc agree on size for a file the listing names; cat reads
	// the very file ls just showed. ls/cat can never disagree.
	if out := run(h, "ls /etc"); !strings.Contains(out, "passwd") {
		t.Fatalf("ls /etc did not name passwd: %q", out)
	}
	lsFields := strings.Fields(firstLineWith(run(h, "ls -l /etc/passwd"), "passwd"))
	if len(lsFields) < 9 {
		t.Fatalf("unexpected ls -l layout: %v", lsFields)
	}
	lsSize, err := strconv.Atoi(lsFields[len(lsFields)-5])
	if err != nil {
		t.Fatalf("could not parse ls -l size: %v", lsFields)
	}
	wcSize, ok := leadingIntLine(run(h, "wc -c /etc/passwd"), "passwd")
	if !ok {
		t.Fatal("could not parse wc -c size")
	}
	if lsSize != wcSize {
		t.Fatalf("ls -l size %d disagrees with wc -c %d for /etc/passwd", lsSize, wcSize)
	}
	if body := run(h, "cat /etc/passwd"); !strings.Contains(body, "root:x:0:0") {
		t.Fatalf("cat of the file ls just listed did not read coherently: %q", body)
	}

	// HOP 4: every way of asking "who is this host" returns one identity.
	if osr := run(h, "cat /etc/os-release"); !strings.Contains(osr, p.PrettyName) {
		t.Fatalf("/etc/os-release disagrees with persona %q: %q", p.PrettyName, osr)
	}
	if hn := run(h, "cat /etc/hostname"); !strings.Contains(hn, p.Hostname) {
		t.Fatalf("/etc/hostname disagrees with persona %q: %q", p.Hostname, hn)
	}
	if una := run(h, "uname -a"); !strings.Contains(una, p.KernelRel) || !strings.Contains(una, p.Hostname) {
		t.Fatalf("uname -a disagrees with the persona kernel/host: %q", una)
	}

	// HOP 5: the per-session overlay is coherent across create, read and delete.
	run(h, "cd /tmp")
	run(h, "echo pwned > /tmp/stage.sh")
	if out := run(h, "ls /tmp"); !strings.Contains(out, "stage.sh") {
		t.Fatalf("overlay create not listed: %q", out)
	}
	if out := run(h, "cat /tmp/stage.sh"); !strings.Contains(out, "pwned") {
		t.Fatalf("overlay file did not read back its contents: %q", out)
	}
	run(h, "mkdir /tmp/loot")
	if out := run(h, "ls /tmp"); !strings.Contains(out, "loot") {
		t.Fatalf("mkdir not reflected in ls: %q", out)
	}
	run(h, "rm /tmp/stage.sh")
	if out := run(h, "ls /tmp"); strings.Contains(out, "stage.sh") {
		t.Fatalf("removed overlay file still listed: %q", out)
	}
	if out := run(h, "cat /tmp/stage.sh"); !strings.Contains(out, "No such file") {
		t.Fatalf("removed overlay file still readable: %q", out)
	}

	// HOP 6: a download is faked: the URL is captured, but nothing connects.
	dlURL := "http://" + sink.Addr().String() + "/stage2.bin"
	run(h, "wget "+dlURL)
	e, ok := h.WaitEvent("DOWNLOAD_ATTEMPT", 2*time.Second)
	if !ok {
		t.Fatal("wget did not log a DOWNLOAD_ATTEMPT")
	}
	if !strings.Contains(e.URL, sink.Addr().String()) {
		t.Fatalf("download URL not captured: %q", e.URL)
	}
	time.Sleep(150 * time.Millisecond) // give any (buggy) real fetch time to land
	if atomic.LoadInt32(&dialed) != 0 {
		t.Fatal("the download opened a real outbound connection: the no-egress boundary is breached")
	}

	// The whole session stitches together under one identity.
	if e, ok := h.FindEvent("SESSION_START"); !ok || e.Session == "" {
		t.Fatal("session was not correlated by a stable id")
	}
}

// TestOverlayEvaporatesAcrossSessions proves the slice's overlay is per-session: a
// file one attacker "creates" is invisible to a second connection over the same
// base filesystem, and never reaches the host. Two harnesses share one *vfs.FS, as
// two real connections to the same honeypot do.
func TestOverlayEvaporatesAcrossSessions(t *testing.T) {
	p := persona.GenerateProfile("full")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := testharness.New(telnet.New(fs, p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	defer h1.Close()
	h2, err := testharness.New(telnet.New(fs, p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	login(t, h1, p, "root")
	login(t, h2, p, "root")

	run(h1, "echo ghost > /tmp/ghost")
	if out := run(h1, "ls /tmp"); !strings.Contains(out, "ghost") {
		t.Fatalf("session 1 cannot see its own overlay file: %q", out)
	}
	if out := run(h2, "ls /tmp"); strings.Contains(out, "ghost") {
		t.Fatalf("session 2 saw session 1's overlay file: the overlay is not per-session: %q", out)
	}
	if out := run(h2, "cat /tmp/ghost"); !strings.Contains(out, "No such file") {
		t.Fatalf("session 2 could read session 1's overlay file: %q", out)
	}
}

// TestShellWritesNoHostByte is the behavioural twin of the structural import
// guardrail for the write boundary: an attacker who "creates" a file gets a
// coherent illusion from the in-memory overlay, while the real host filesystem
// gains nothing. A regression that made the overlay write through to disk would
// turn the honeypot into an attacker-controlled malware drop; this canary fails
// loudly if that ever happens.
func TestShellWritesNoHostByte(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// Unique paths under /tmp: it exists in the VFS (so the overlay write succeeds
	// and the illusion is real) and on the host (so a write-through regression would
	// actually leave a file behind at the same absolute path, where we detect it).
	base := "/tmp/sweetty_canary_" + strconv.Itoa(os.Getpid())
	run(h, "echo pwned > "+base+".sh")
	run(h, "cp /etc/passwd "+base+".copy")
	run(h, "touch "+base+".touch")

	// The illusion holds inside the session...
	if out := run(h, "cat "+base+".sh"); !strings.Contains(out, "pwned") {
		t.Fatalf("overlay write was not readable back in-session: %q", out)
	}
	// ...but not one byte reached the host filesystem.
	for _, suffix := range []string{".sh", ".copy", ".touch"} {
		if _, err := os.Stat(base + suffix); !os.IsNotExist(err) {
			t.Fatalf("the honeypot wrote attacker bytes to the host at %q (err=%v): the write boundary is breached", base+suffix, err)
		}
	}
}
