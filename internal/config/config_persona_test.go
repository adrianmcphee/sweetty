package config

import "testing"

func TestPersonaPathResolves(t *testing.T) {
	cases := []struct {
		name        string
		personaFile string
		configPath  string
		want        string
	}{
		{"default beside config", "", "/opt/sweetty/config.json", "/opt/sweetty/persona.json"},
		{"absolute override", "/opt/sweetty/state/persona.json", "/opt/sweetty/config.json", "/opt/sweetty/state/persona.json"},
		{"relative to config dir", "state/persona.json", "/opt/sweetty/config.json", "/opt/sweetty/state/persona.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Config{PersonaFile: tc.personaFile}.PersonaPath(tc.configPath)
			if got != tc.want {
				t.Errorf("PersonaPath = %q, want %q", got, tc.want)
			}
		})
	}
}
