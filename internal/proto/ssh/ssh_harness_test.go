package ssh_test

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/proto/ssh"
	"sweetty/internal/testharness"
)

func TestSSHBannerFromPersonaAndClientCapture(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(ssh.NewTarpit(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	banner, ok := h.ReadUntil("SSH-2.0-", 2*time.Second)
	if !ok {
		t.Fatalf("no SSH banner: %q", banner)
	}
	if !strings.Contains(banner, p.OpenSSHVer) {
		t.Fatalf("SSH banner not drawn from persona %q: %q", p.OpenSSHVer, banner)
	}

	// The client identification string is captured.
	h.SendLine("SSH-2.0-libssh2_1.10.0")
	time.Sleep(300 * time.Millisecond)
	if !h.HasEvent("SSH_CLIENT") {
		t.Fatal("client banner was not logged")
	}
}

// TestSSHKexCaptured proves the first key-exchange packet is captured for
// fingerprinting: after the client banner, the service reads the next line and
// records it as SSH_KEX with a non-empty hex dump.
func TestSSHKexCaptured(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(ssh.NewTarpit(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if _, ok := h.ReadUntil("SSH-2.0-", 2*time.Second); !ok {
		t.Fatal("no SSH banner")
	}

	h.SendLine("SSH-2.0-OpenSSH_9.6")
	// 32 bytes of KEXINIT-shaped filler, none of which is CR, LF, or NUL, so the
	// line read captures them intact before the terminating newline.
	kex := make([]byte, 32)
	for i := range kex {
		kex[i] = byte(0x14 + i)
	}
	h.SendBytes(append(kex, '\n'))

	e, ok := h.WaitEvent("SSH_KEX", 2*time.Second)
	if !ok {
		t.Fatal("no SSH_KEX event")
	}
	if e.Data == "" {
		t.Fatal("SSH_KEX captured no data")
	}
}
