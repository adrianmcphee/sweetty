# SweeTTY: Architecture

## Data flow

A connection arrives on a listener. The server frames it, records the source, and
hands the bytes to the protocol handler for that port. Every handler reads the
host's identity and filesystem from one shared, read-only source of truth (the
persona and the virtual filesystem), so no two surfaces can disagree. Every
notable action is written to the append-only JSON event log.

```
client -> listener -> server (source attribution, scan detection)
                         -> protocol handler -> shell / virtual filesystem
                         -> event log (line-delimited JSON)
```

## The safety boundary

Handlers may read the persona and the virtual filesystem and may write to the
event log. They may not import infrastructure, open outbound connections, or
touch the host disk. An attacker's writes land in a per-session overlay that
evaporates when the session ends.
