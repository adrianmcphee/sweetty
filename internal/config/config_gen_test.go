package config

import (
	"testing"

	"sweetty/internal/persona"
)

func TestGenerateFromPersona(t *testing.T) {
	p := persona.GenerateProfile("full")
	cfg := Generate(p)
	if len(cfg.Listeners) != len(p.Services) {
		t.Fatalf("listeners %d != services %d", len(cfg.Listeners), len(p.Services))
	}
	for i, s := range p.Services {
		if cfg.Listeners[i].Protocol != s.Protocol || cfg.Listeners[i].Port != s.Port {
			t.Errorf("listener %d mismatch: %+v vs %+v", i, cfg.Listeners[i], s)
		}
	}
	if cfg.PortalPort < 20000 || cfg.PortalPort >= 60000 {
		t.Errorf("portal port %d out of expected high range", cfg.PortalPort)
	}
	for _, lc := range cfg.Listeners {
		if lc.Port == cfg.PortalPort {
			t.Errorf("portal port collides with service port %d", lc.Port)
		}
	}
}

func TestPortalPortVaries(t *testing.T) {
	p := persona.Generate()
	seen := map[int]bool{}
	for range 25 {
		seen[Generate(p).PortalPort] = true
	}
	if len(seen) < 5 {
		t.Fatalf("portal port not varied: %d distinct in 25", len(seen))
	}
}
