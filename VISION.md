# SweeTTY: Product Vision

## In one line

A single Go binary that impersonates a vulnerable Linux server across many ports at once, records every move an attacker makes, wastes their time on purpose, and never executes a thing they send.

## Why it exists

Any service exposed to the internet is found and probed within minutes, mostly by automation, occasionally by a human. Those probes are signal: the credentials people try, the commands they run once they think they are in, the URLs they pull their next stage from, and the tooling they reach for. That signal is normally invisible, because a real service either rejects the attacker (and logs nothing useful) or gets compromised (and logs nothing you can trust afterward).

SweeTTY exists to make that signal cheap to collect and safe to keep. It is a deception surface with no real services behind it, deployed on a host that exists only to be attacked. Because nothing legitimate ever connects to it, **every connection is, by definition, hostile and worth recording.** The honeypot's whole job is to look real long enough to learn something, and to be honest in its logs even though it is dishonest to the attacker.

## Who it is for

- **Threat researchers and blue teams** who want first-hand, current intelligence on what is sweeping their address space: which botnets, which credential lists, which payload hosts, which CVEs are being weaponised this week.
- **Operators running an isolated honeypot** who want a single drop-in binary they run as-is, with no framework to assemble and babysit.
- **Anyone studying attacker behaviour** who needs a faithful transcript of a session, replayable exactly as the attacker saw it, rather than a lossy summary.

## What good looks like

Two audiences meet SweeTTY, and success is defined differently for each.

**For the automated scanner**, success is frustration and capture. The bot finds an open port, gets a banner that matches a known-vulnerable target, fires its credential list and its loader one-liner, and walks away believing it succeeded. Every credential, every command, and every payload URL is logged before anything appears to work, and nothing the bot sent ever ran.

**For the human operator**, success is engagement and exposure. The shell holds up under probing: `cd` actually changes directory and the prompt follows; `ls -l /etc` and `cat /etc/passwd` agree with each other because they read the same filesystem; `whoami` says root and `cat /etc/shadow` works the way it would for root; a download completes and the file lands, an install finishes, and a cron job they add is there when they list it. The box behaves like the already-compromised host they think they own, while a compile still grinds and fails the way a half-broken toolchain would. The longer a curious human stays to figure out why this box is *almost* right, the more of their tooling, their tradecraft, and their infrastructure they reveal, and all of it lands in the log.

**For the operator running it**, success is a quiet binary and a loud dashboard. It starts, binds its ports, and gets out of the way. When something interesting happens, a portal reached over an SSH tunnel shows it live, colour-coded, and lets them pull up a single attacker's entire history: every session, every credential tried, every command run, every payload reached for, in order, and the terminal session replayable exactly as the attacker saw it.

## Design doctrine

These are the principles the product is built on, and the code and tests enforce them.

### 1. Coherence is the only realism that matters

A honeypot is caught on its contradictions. A careful human needs about a minute and two or three commands to find one: a directory listing that names a file the system then cannot read, a kernel version that disagrees with the SSH banner, a root shell that is somehow forbidden from reading its own files, a directory listing that reshuffles between runs.

So the doctrine is **single source of truth, everywhere.** One real virtual filesystem backs every file command, so listings and reads can never disagree. One persona definition (distribution, kernel, hostname, primary user, SSH version) drives `uname`, the banners, the config files, and the prompt, so they cannot diverge. System-tool output is generated from session state, so repeated calls differ the way a live box differs. The deception is allowed to be smaller than a real server; it is never allowed to be internally inconsistent.

### 2. Capture intent, never grant capability

SweeTTY records what an attacker *tries* to do and grants none of it, but the fake is convincing, not obstructive. A download completes and an inert file lands; a package install finishes; a cron job and an SSH key persist for the session; an `scp` to the attacker's own box reports success. Yet not a single byte is fetched from the network, nothing they send is ever run, and every "file" they create lives in a per-session, in-memory overlay that evaporates on disconnect and never touches the host disk. Payloads that arrive in-band (a pasted script, a base64 blob, an HTTP body) are logged and fingerprinted, never executed. Letting the action *appear* to succeed is what draws the whole kill chain (download, run, install, persist, exfiltrate) into the log; a box that refuses everything only teaches a bot it found a honeypot.

This boundary is enforced in the code itself, so no configuration can turn it off. A honeypot that fetches the URLs attackers hand it is a server-side request forgery primitive pointed at the internet on their behalf; one that writes their uploads to disk is a malware drop they control. SweeTTY does neither. It reads nothing from the real host's `/proc` or `/sys`, so it cannot leak the honeypot's true hardware or identity, and it reaches out to nothing an attacker names.

### 3. One self-contained binary

Everything ships inside one statically-linked Go binary: the protocols, the fake shell, the virtual filesystem, and the management portal. The fake filesystem is embedded at build time, so there is nothing on disk for an attacker who breaks containment to discover or tamper with, and nothing for an operator to install, mount, or keep in sync. Dependencies are kept to a deliberate minimum so the binary stays small, auditable, and easy to trust on a box you have intentionally exposed to attack.

### 4. Honest, structured, tamper-evident logging

The product is only as good as its log. Every event is one self-describing JSON object on its own line, carrying a stable per-session identity so distinct attackers behind the same address never blur together, and so a session can be reconstructed end to end. Inputs are sanitised before they are written, so an attacker cannot inject forged log lines by embedding newlines in a command. The log is designed to be made append-only at the OS level, so a shell that somehow escaped the deception still could not rewrite the record of itself.

### 5. Time is a weapon, used deliberately

Holding a connection open costs the attacker a thread, a worker, or a human's patience. SweeTTY spends that currency on purpose: tarpit ports hold scanners open doing nothing, and slow operations stall the way a loaded box would. But time-wasting is a tunable trade, spent where it pays and eased where it would show. Tactics obvious enough to become a signature (a `find` that trickles for five minutes when the real command returns instantly) are strongest on the pure tarpit ports and lightest on the interactive shell a sophisticated operator will benchmark; there, an action is more often allowed to *appear to succeed* than to stall, because a command that hangs when the real one returns instantly is itself a tell. The goal is to cost the attacker more than it costs us, without the cost itself becoming the tell.

### 6. The management plane leaves no footprint

The facade is loud; the management plane is silent. There is no management port for an attacker to find. The portal binds loopback and is never exposed to the network: an operator reaches it only by forwarding the box's real SSH to it, so SSH key authentication is the single strong front door and the portal carries no login of its own to guess at, leak from, or rotate. The real SSH does not advertise as the admin door either; it lives on a randomized, http-like port that blends in among web services and differs on every instance, so a scan of the box turns up the honeypot's ports and what looks like one more web service, never an obvious way in. To the operator on the other end of the tunnel, the same portal is a live, drill-down, replayable view of everything the honeypot has seen.

### 7. Unpredictable from the source

SweeTTY is open source, so an attacker can read exactly how it works. That must not help them recognise a live instance. Every identifying value is generated per instance on first run and persisted only on that host, never in the repository: the hostname, the entire internal address range and the neighbouring hosts, the SSH host-key fingerprint, the machine id, the disk UUIDs, the password hashes, the application secrets, and the boot time. The shape of the deployment varies too: which services are exposed, which persona and software version each one presents, and the randomized http-like port the real management SSH hides behind are all chosen per instance. The source reveals the method and the templates; every constant an attacker could match against a box in the wild is generated per instance and absent from it. The values that stay fixed are fixed on purpose, because they are what every real host of this kind already shares: the Linux distribution family, the conventional account names, the standard ports a service is expected to answer on. Predictability is the tell, and this principle removes it.

### 8. Bait that bites back

The honeypot does not only wait to be typed at; it plants things worth stealing. Files with compelling, exfiltration-worthy names sit on a neighbouring host an attacker can pivot into, and a command that looks like a password vault or a wallet balance sits in the shell. None of it is real, and nothing reveals the trick in place: the bait is not laid out in the open but buried at an obscure, per-instance-random path an attacker reaches only by following the breadcrumb trail the box leaves for them, and `ls`, `stat`, and `file` all show a normal image until they try to use one. A legitimate user never runs the vault or digs out the "backups", so every touch is, by construction, an attacker: a near-zero-false-positive signal. The reveal is the payoff: however they try to open a bait file, they get a colour-ANSI surprise instead of a secret, and the operator gets the commands they ran and proof of what they came to take and how they tried to take it.

## Non-goals

Stating these keeps the product honest about what it is not.

- **Not a production service.** SweeTTY has no real users and serves no real traffic. It is an instrument, deployed where any connection is already suspect.
- **Not a malware execution sandbox.** It captures payloads and intent; it does not detonate, emulate, or analyse what it captures. That is a separate, downstream job.
- **Not magically undetectable.** A determined adversary with deep, specific knowledge of exactly what a given real host should contain can still find a seam. But because every instance's identity, service set, software versions, and management SSH port are randomized and absent from the source, reading the code does not help, and no two instances share a signature. The bar is to survive the first minutes of skeptical probing by someone who has read the source, which is where the intelligence is won or lost. One seam is conceded by design: the interactive SSH service completes a real handshake, so its key-exchange and cipher list (its HASSH) are those of this Go SSH stack and do not match a genuine OpenSSH server, even though the banner does. That is the deliberate price of capturing a full SSH session rather than only a banner, and a pure banner-and-tarpit with no such fingerprint stays available for ports where deflection matters more than interaction.
- **Not a defensive control.** It does not block, filter, or protect anything. It watches, and it learns.

## The measure of the product

SweeTTY succeeds when a bot leaves convinced it won, a human stays longer than they meant to, the operator can replay exactly what happened, and at no point did the box fetch a byte from the network, touch the host disk, or run a single thing an attacker asked it to.
