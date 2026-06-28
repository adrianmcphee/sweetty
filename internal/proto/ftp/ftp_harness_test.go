package ftp_test

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/proto/ftp"
	"sweetty/internal/testharness"
)

func TestFTPBannerAndCredentialCapture(t *testing.T) {
	p := persona.GenerateProfile("ftp")
	h, err := testharness.New(ftp.New(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	banner, ok := h.ReadUntil("220", 2*time.Second)
	if !ok {
		t.Fatalf("no FTP 220 banner: %q", banner)
	}

	h.SendLine("USER admin")
	if _, ok := h.ReadUntil("331", 2*time.Second); !ok {
		t.Fatal("no 331 after USER")
	}
	h.SendLine("PASS s3cr3t!")
	if _, ok := h.ReadUntil("530", 2*time.Second); !ok {
		t.Fatal("no 530 after PASS")
	}

	e, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("ftp did not capture a credential")
	}
	if e.Username != "admin" || e.Password != "s3cr3t!" {
		t.Fatalf("captured creds = %q / %q", e.Username, e.Password)
	}
}

func TestFTPQuit(t *testing.T) {
	p := persona.GenerateProfile("ftp")
	h, err := testharness.New(ftp.New(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.ReadUntil("220", 2*time.Second)
	h.SendLine("QUIT")
	out, ok := h.ReadUntil("221", 2*time.Second)
	if !ok || !strings.Contains(out, "221") {
		t.Fatalf("QUIT not acknowledged: %q", out)
	}
}
