package ssh

import (
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
)

func TestNewNameAndClientFirst(t *testing.T) {
	p := persona.Generate()
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	for _, proto := range []interface {
		Name() string
		ClientFirst() bool
	}{
		New(fs, p, ""),
		NewTarpit(p),
	} {
		if got := proto.Name(); got != "ssh" {
			t.Errorf("Name() = %q, want %q", got, "ssh")
		}
		if proto.ClientFirst() {
			t.Error("ClientFirst() = true, want false (the SSH server speaks first)")
		}
	}
}
