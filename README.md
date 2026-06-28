# SweeTTY

A multi-protocol honeypot in a single Go binary. SweeTTY listens on many ports at
once, presents a convincing fake service on each, and records every interaction
as structured JSON. A built-in web portal gives you a live dashboard over the
activity, bound to loopback and reached over an SSH tunnel so it leaves no
management footprint on the network.

The design goal is simple: every attacker interaction is logged, automated
scanners are frustrated, and human operators are kept engaged long enough to
reveal their tooling, payloads, and command-and-control infrastructure.

## What it does

- **Listens on many ports**, each running an independent fake service (telnet,
  SSH, HTTP, HTTPS, FTP).
- **Presents a real interactive shell** over SSH and telnet, backed by a coherent
  **virtual filesystem**.
- **Lets attackers believe they are winning, inside a sealed boundary.**
- **Captures credentials, commands, payloads, and download URLs** across every
  protocol.
- **Detects port scans**: anything that connects and sends nothing is logged and
  dropped.
- **Logs everything as line-delimited JSON**, ready for `jq` or the portal.
- **Serves a live dashboard**, bound to loopback and reached over an SSH tunnel.

## Quick start

```bash
go build -o sweetty ./cmd/sweetty
./sweetty init
./sweetty
```

## Management portal

The portal binds loopback and serves plain HTTP with no application auth. Reach
it by forwarding the port over SSH:

```bash
ssh -L 8443:127.0.0.1:8443 operator@honeypot-host
```

Operator consoles (such as an HAProxy stats page) named in `admin_consoles` are
reverse-proxied into the dashboard and reached over the same tunnel.
