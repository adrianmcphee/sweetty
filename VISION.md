# SweeTTY: Product Vision

## In one line

A multi-protocol honeypot in a single Go binary that owns the exact bytes on the
wire, so an attacker cannot tell it from a real, slightly neglected Linux host.

## Why it exists

Off-the-shelf honeypots are recognisable: telltale banners, incoherent
filesystems, shells that contradict themselves under inspection. An attacker who
notices leaves, and takes the intelligence with them. SweeTTY is built so that
every surface tells one coherent story.

## Who it is for

Operators who want first-party threat intelligence from an isolated host or
network segment where any connection is, by definition, unsolicited.

## Design doctrine

### 1. Coherence is the only realism that matters

Every command, file, and banner is answered from one source of truth, so nothing
an attacker reads contradicts anything else they read.

### 2. Capture intent, never grant capability

Downloads appear to succeed, installs appear to finish, yet nothing runs, nothing
is fetched, and nothing touches the host disk.

### 3. One self-contained binary

No runtime dependencies, no database, no sidecars. The whole sensor is one Go
binary plus a config file.

### 4. Honest, structured, tamper-evident logging

Every event is one line of JSON, written append-only, ready for ingestion.
