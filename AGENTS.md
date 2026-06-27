# Agent Instructions: SweeTTY

## Hard rules (do not violate)

1. **No agent or AI attribution anywhere.** No `Co-Authored-By`, no "Generated
   with", no tool names, no robot emoji, in commit messages, code, or docs. The
   commit-msg hook enforces this; install it with `make hooks`.
2. **No em dashes** in prose or comments. Use commas, colons, or restructure.
3. **The honeypot owns the bytes on the wire.** Protocol emulations are written
   against the standard library so the exact response bytes are under our control.

## What this is

A multi-protocol honeypot in a single Go binary. Listeners present fake services;
a shared persona and virtual filesystem keep every surface coherent; every event
is logged as line-delimited JSON.

## Architecture conventions

- `internal/domain` logic must not import infrastructure.
- Handlers read the persona and the virtual filesystem; they never touch the host
  disk or open outbound connections.

## Verification

`make check` is the gate: gofmt, vet, build, and the full test suite.
