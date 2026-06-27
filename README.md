# SweeTTY

A multi-protocol honeypot in a single Go binary. SweeTTY presents a convincing
fake service on each port it listens on and records every interaction as
structured JSON.

The design goal is simple: every attacker interaction is logged, automated
scanners are frustrated, and human operators are kept engaged long enough to
reveal their tooling, payloads, and command-and-control infrastructure.

SweeTTY is built from scratch in Go and kept deliberately dependency-light. The
protocol emulations, the fake shell, and the virtual filesystem are implemented
directly against the standard library, so the honeypot owns the exact bytes on
the wire.

## Status

Early scaffolding. The virtual filesystem comes first; protocols and the
management portal build on top of it.
