// Package config owns the on-disk JSON config: its schema, defaults, loading,
// and writing.
package config

import (
	"encoding/json"
	mrand "math/rand/v2"
	"os"

	"sweetty/internal/persona"
)

type Config struct {
	PortalPort        int            `json:"portal_port"`
	LogFile           string         `json:"log_file"`
	ProxyProtocol     bool           `json:"proxy_protocol,omitempty"`      // parse an HAProxy PROXY header per connection to recover the real source IP (HAProxy edge topology)
	ProxyTrustedCIDRs []string       `json:"proxy_trusted_cidrs,omitempty"` // peer networks (besides loopback) allowed to present a PROXY header; a header from any other peer is ignored so a direct attacker cannot spoof the source
	PortalBind        string         `json:"portal_bind,omitempty"`         // host the portal binds; default 127.0.0.1, reached via an SSH tunnel. Set 0.0.0.0 to expose it directly (no application auth, so only behind a trusted boundary)
	GeoIPFile         string         `json:"geoip_file,omitempty"`          // optional operator IP-to-country CSV, read only by the portal
	RecordDir         string         `json:"record_dir,omitempty"`          // optional directory for per-session asciinema cast recordings; empty disables recording
	AdminConsoles     []AdminConsole `json:"admin_consoles,omitempty"`      // operator consoles reverse-proxied through the portal, reached over the same SSH tunnel
	Listeners         []Listener     `json:"listeners"`
}

// AdminConsole is an operator-facing web console (such as the HAProxy stats page)
// that the portal reverse-proxies, reached over the same SSH tunnel as the
// portal. The target is fixed here by the operator and never derived from a
// request, so this is not an open proxy: the operator reaches only the consoles
// the instance explicitly lists, each on the local host.
type AdminConsole struct {
	Name        string `json:"name"`                   // url-safe slug, e.g. "haproxy"
	Label       string `json:"label,omitempty"`        // display label in the dashboard
	Target      string `json:"target"`                 // upstream base URL, e.g. http://127.0.0.1:19000/
	StripPrefix bool   `json:"strip_prefix,omitempty"` // strip /dashboard/console/<name> before forwarding; default false forwards the full path so an upstream with absolute links (HAProxy stats) works when configured to serve under the mount path
}

type Listener struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // telnet | ssh | http | https | ftp
	Persona  string `json:"persona,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		PortalPort: 8443,
		PortalBind: "127.0.0.1",
		LogFile:    "sweetty.log",
		Listeners: []Listener{
			{Port: 21, Protocol: "ftp"},
			{Port: 22, Protocol: "ssh"},
			{Port: 23, Protocol: "telnet", Persona: "ubuntu"},
			{Port: 80, Protocol: "http", Persona: "wordpress"},
			{Port: 443, Protocol: "https"},
			{Port: 2323, Protocol: "telnet", Persona: "ubuntu"},
			{Port: 8080, Protocol: "http", Persona: "tomcat"},
		},
	}
}

// Generate builds a config for an instance from its persona: a randomized portal
// port and the persona's chosen service set as listeners. This is what `init`
// writes, so the exposed services and the portal port vary per instance.
func Generate(p *persona.Persona) Config {
	listeners := make([]Listener, 0, len(p.Services))
	for _, s := range p.Services {
		listeners = append(listeners, Listener{Port: s.Port, Protocol: s.Protocol, Persona: s.Style})
	}
	return Config{
		PortalPort: randomPortalPort(),
		PortalBind: "127.0.0.1",
		LogFile:    "sweetty.log",
		Listeners:  listeners,
	}
}

// randomPortalPort returns a high port that does not collide with the honeypot
// service ports and is not a fixed well-known value an attacker could probe for.
func randomPortalPort() int {
	return 20000 + mrand.IntN(40000)
}

// Write writes cfg to path, failing if the file already exists, with mode 0600.
func Write(cfg Config, path string) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(out)
	return err
}

// Load reads the config file over a default base, so missing fields keep
// sensible defaults. Returns an error only when the file is unreadable or invalid.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	// Let the file be authoritative for listeners when it specifies them.
	cfg.Listeners = nil
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.PortalPort == 0 {
		cfg.PortalPort = 8443
	}
	if cfg.LogFile == "" {
		cfg.LogFile = "sweetty.log"
	}
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = DefaultConfig().Listeners
	}
	return cfg, nil
}

// WriteDefault writes the default config, failing if the file already
// exists, with mode 0600.
func WriteDefault(path string) error {
	out, err := json.MarshalIndent(DefaultConfig(), "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(out)
	return err
}
