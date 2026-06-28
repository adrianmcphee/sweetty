# SweeTTY: Testing Strategy

## Invariants over line coverage

The suite proves invariants an attacker would probe, not lines. The central
invariant is coherence: every surface tells one host's story, and nothing a
visitor reads contradicts anything else they read.

## Two adversaries

Tests are written against two adversaries: the automated scanner that fingerprints
banners and timing, and the human operator who inspects the filesystem and the
shell for contradictions. A change that would let either tell SweeTTY from a real
host is a failing test.

## One vertical slice, proven end to end

The virtual filesystem is the spine: `cd`, `ls`, `cat`, `find`, `stat`, `head`,
and `tail` are proven to read from one consistent tree, with an attacker's writes
confined to a per-session overlay that never reaches the host disk.

## What the suite proves

- Each protocol's bytes on the wire match real captures, down to header order and
  reply codes.
- A bare connect is a port scan; a flood is shed; a handler panic does not take
  the listener or the log down.
- No handler imports infrastructure, opens an outbound connection, or injects the
  event log.
