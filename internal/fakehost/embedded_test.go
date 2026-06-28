package fakehost

import (
	"strings"
	"testing"

	"sweetty/internal/persona"
)

func renderFile(t *testing.T, p *persona.Persona, path string) string {
	t.Helper()
	fsys, err := Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	b, err := fsys.NewSession("/").ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// The /proc identity files are templated against the persona, so the same shipped
// template must render as ARM for an embedded board and x86 for a server, with no
// architecture from one bleeding into the other and no residual {{placeholder}}.
// This is the render-layer proof that the byte the attacker reads matches the
// persona the rest of the box is built from.
func TestProcIdentityRendersPerArch(t *testing.T) {
	emb := persona.GenerateProfile("legacy")
	srv := persona.GenerateProfile("web")

	embCPU := renderFile(t, emb, "/proc/cpuinfo")
	embVer := renderFile(t, emb, "/proc/version")
	srvCPU := renderFile(t, srv, "/proc/cpuinfo")
	srvVer := renderFile(t, srv, "/proc/version")

	// Embedded reads as ARM and never leaks Intel/x86.
	if !strings.Contains(embCPU, "CPU architecture: 8") || !strings.Contains(embCPU, "0xd08") {
		t.Errorf("embedded /proc/cpuinfo is not ARM:\n%s", embCPU)
	}
	if strings.Contains(embCPU, "GenuineIntel") || strings.Contains(embCPU, "Xeon") {
		t.Errorf("embedded /proc/cpuinfo leaks x86 identity:\n%s", embCPU)
	}
	if !strings.Contains(embVer, "arm64") || strings.Contains(embVer, "amd64") {
		t.Errorf("embedded /proc/version is not arm64: %q", embVer)
	}

	// Server keeps its exact x86 identity.
	if !strings.Contains(srvCPU, "GenuineIntel") {
		t.Errorf("server /proc/cpuinfo lost its x86 identity:\n%s", srvCPU)
	}
	if strings.Contains(srvCPU, "0xd08") {
		t.Errorf("server /proc/cpuinfo leaks ARM identity:\n%s", srvCPU)
	}
	if !strings.Contains(srvVer, "amd64") {
		t.Errorf("server /proc/version is not amd64: %q", srvVer)
	}

	// The kernel release in /proc/version agrees with uname -r on both arches.
	if !strings.Contains(embVer, emb.KernelRel) {
		t.Errorf("embedded /proc/version disagrees with uname -r %q: %q", emb.KernelRel, embVer)
	}
	if !strings.Contains(srvVer, srv.KernelRel) {
		t.Errorf("server /proc/version disagrees with uname -r %q: %q", srv.KernelRel, srvVer)
	}

	for _, s := range []string{embCPU, embVer, srvCPU, srvVer} {
		if strings.Contains(s, "{{") {
			t.Errorf("residual template placeholder in rendered file:\n%s", s)
		}
	}
}
