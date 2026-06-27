package persona

import (
	"crypto/ed25519"
	"testing"
)

// TestAcceptOnlyPerInstancePasswords proves the credential policy: only the two
// real accounts (root and the primary user) authenticate, each with its own
// per-instance random password, and no universally-common password opens the box.
// This is the behaviour that keeps the working credential unpredictable per
// instance rather than a constant readable from the source.
func TestAcceptOnlyPerInstancePasswords(t *testing.T) {
	p := Generate()

	if !p.Accept("root", p.RootPassword) {
		t.Errorf("root with the per-instance password was rejected (%q)", p.RootPassword)
	}
	if !p.Accept(p.Username, p.UserPassword) {
		t.Errorf("%s with the per-instance password was rejected (%q)", p.Username, p.UserPassword)
	}

	// Wrong password for a real account is refused.
	if p.Accept("root", p.RootPassword+"-wrong") {
		t.Error("root accepted a wrong password")
	}
	// An account that does not exist on the host is refused even with a real password.
	if p.Accept("nonexistent", p.RootPassword) {
		t.Error("an unknown user authenticated")
	}
	// Ubiquitous weak passwords the generator can never produce (no trailing digits /
	// no word prefix) must not open the instance: the working credential is random.
	for _, common := range []string{"", "root", "admin", "123456", "toor", "letmein"} {
		if p.Accept("root", common) {
			t.Errorf("common password %q opened the box; the credential is meant to be per-instance random", common)
		}
	}
}

// TestPasswordsVaryPerInstance proves the working passwords are not pinned to a
// single constant across instances.
func TestPasswordsVaryPerInstance(t *testing.T) {
	const N = 20
	roots := map[string]bool{}
	for range N {
		p := Generate()
		roots[p.RootPassword] = true
		if p.RootPassword == "" || p.UserPassword == "" {
			t.Fatal("a per-instance password was empty")
		}
	}
	if len(roots) < 2 {
		t.Errorf("root password observed only %d distinct value(s) over %d gens; looks pinned", len(roots), N)
	}
}

// TestSSHHostKeyStableAndValid proves the host key is a real ed25519 key rebuilt
// deterministically from the persisted seed, so it is stable across restarts (the
// same persona always yields the same key) and usable by the SSH stack.
func TestSSHHostKeyStableAndValid(t *testing.T) {
	p := Generate()

	k1, err := p.SSHHostKey()
	if err != nil {
		t.Fatalf("host key from a freshly generated persona failed: %v", err)
	}
	if len(k1) != ed25519.PrivateKeySize {
		t.Fatalf("host key is not a full ed25519 private key: len %d", len(k1))
	}
	k2, err := p.SSHHostKey()
	if err != nil {
		t.Fatalf("second host key derivation failed: %v", err)
	}
	if !k1.Equal(k2) {
		t.Error("the host key changed between derivations from the same seed; it must be stable")
	}

	// Two instances have different host keys.
	other, _ := Generate().SSHHostKey()
	if k1.Equal(other) {
		t.Error("two instances produced the same SSH host key")
	}

	// A persona with no seed (an older instance) reports an error instead of an
	// unstable key, so the SSH service can fall back to the tarpit.
	stale := Generate()
	stale.SSHHostKeySeed = ""
	if _, err := stale.SSHHostKey(); err == nil {
		t.Error("a persona with no host key seed must report an error, not improvise a key")
	}
}
