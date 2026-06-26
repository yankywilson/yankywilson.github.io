---
layout: post
title: "Reverse Engineering JDY: Decrypting a Volt Typhoon-Lineage Recon Botnet"
date: 2026-06-26 08:00:00 -0400
categories: [threat-intelligence, reverse-engineering]
tags: [JDY, VoltTyphoon, botnet, MIPS, malware-analysis, OSINT, DFIR]
---

**JDY** is a China-nexus reconnaissance botnet in the Volt Typhoon / KV-botnet
ecosystem (MITRE **G1017**). It fingerprints internet-exposed edge and SOHO devices at
scale and pivots to newly disclosed vulnerabilities within hours. It is the **targeting
and prepositioning layer** that makes a follow-on intrusion fast and precise — not an
exploit kit, and not ransomware.

This is a long walk through the investigation: pulling the encrypted tasking channel out
of the implant, tearing down the scan engine and transport classes, documenting the
claims I had to reverse on the bench, and the infrastructure hunt that mattered as much
for what it *didn't* find as for what it did. The full write-up, IOCs, detection content,
and a working decryptor are in the repository:
[github.com/yankywilson/jdy-botnet-threat-analysis](https://github.com/yankywilson/jdy-botnet-threat-analysis/tree/main).

*Classification: TLP:CLEAR. Estimative language per ICD-203. Findings tagged NOVEL /
CORROBORATED / PUBLISHED / EXCLUDED.*

## The sample, and why analysis was static-first

The implant is a **MIPS64 big-endian ELF**, statically linked and stripped, about 3 MB.
The architecture is the first constraint that shaped everything: a MIPS64 BE binary does
not execute in a Windows x86 sandbox, so dynamic detonation against the live tasking
channel was off the table from the start. The analysis was **static-first**.

The toolchain was Ghidra as the primary disassembler and decompiler — loaded as
`MIPS:BE:64`, default compiler, full auto-analysis with the MIPS constant-reference
analyzer enabled, global pointer `gp` at `0x1030c050` — cross-checked at the instruction
level with capstone, pyelftools, and `mips-linux-gnu-objdump`. Network behavior was
corroborated from packet captures of the live dispatch tier, not from running the implant.
The discipline throughout was triangulation: no single decompiler output was trusted on a
load-bearing claim until it was confirmed against a second tool.

Two facts surfaced immediately and shaped the rest of the work. The binary contains **no
exploit code** — it is a scanner and fingerprinter — and it contains **no hardcoded C2
address**. The only IP-shaped strings are a version string, a placeholder, and a library
version. The control host is injected at deploy time by the dropper via a `-s <web_ip>`
flag. Both are **CORROBORATED**, and together they tell you what JDY is: reconnaissance
tooling whose infrastructure is meant to be swapped out.

## Reading the tasking channel

JDY bots pull scanning tasks from a Tor-hidden dispatch service. The tasking payload is
**base64 → AES-128-CBC → JSON**, and recovering that scheme was the core of the work.

The way in was a handful of landmarks. The AES decrypt T-table (`Td0`) sits in `.rodata`;
its GOT-slot cross-reference leads into the AES block function. The key string
`bdb718bdf47cbcde` also sits in `.rodata`; its cross-references land in the tasking
handler. The two meet at the CBC worker, which is identifiable not by any symbol — the
binary is stripped — but structurally, by its XOR-previous-block / save-IV shape, the
classic CBC chaining pattern. From there the chain is: fetch the `probe_task` body,
base64-decode it, run AES-CBC decrypt, parse the result as JSON.

### The published key wasn't a key

This is the detail that matters most, and the one most easily gotten wrong.

Public reporting lists the key as a 32-hex-character string,
`0000000000000000bdb718bdf47cbcde`. Thirty-two characters invites an AES-256 reading. The
binary disagrees. Reading the **bit-length argument** off the register before the
key-schedule call — delay-slot aware — the value is **128**, not 256. And the key string
passed to the schedule is the sixteen ASCII bytes `bdb718bdf47cbcde`, used **raw**, not
hex-decoded.

So what is the leading `0000000000000000`? It is the **IV**, concatenated in front of the
key. The implant's IV is sixteen ASCII `0` bytes — `0x30` repeated sixteen times. The
published value is **IV ∥ KEY**, not a 256-bit key (**NOVEL**).

That single register read is the difference between a decryptor that works and one that
silently emits garbage. It is also a good argument for static reproduction over trusting a
published artifact: the "key" everyone had was correct bytes in the wrong shape.

### The decryptor, and a note on failing loudly

The repo includes [`jdy_decrypt.py`](https://github.com/yankywilson/jdy-botnet-threat-analysis/tree/main),
which implements the recovered scheme and turns a captured `probe_task` body into the
plaintext tasking JSON — the IP ranges, ports, and CVE/fingerprint rules a bot was pointed
at. It auto-detects the IV (`0x30` × 16, falling back to `0x00` × 16), validates PKCS#7
padding, and **fails loudly** when padding does not check out.

The loud-failure design is deliberate. If the tool can't validate padding, the most likely
cause is that the input is not the raw AES blob — HTTP framing was left on it, or the wrong
field was captured — not that the cipher is wrong. The tool says so, so the analyst suspects
the input rather than chasing a phantom in the crypto. A `--selftest` round-trips the whole
scheme so the wiring is re-verifiable anywhere.

## The implant is a toolkit, not a monolith

JDY exposes a family of C++ transport classes with RTTI names and vtables, selected **per
task** rather than hardcoded. The bot is a transport toolkit:

- `meth_des` — the **method-descriptor / dispatcher base class**, the polymorphic base the
  others derive from. Not a DES cipher; not a transport.
- `meth_tcp`, `meth_udp`, `meth_ssl` — TCP, UDP, and TLS transports.
- `meth_tunnel` — a **client connect-out transport**.

The dispatch strategy (`scan_type`) selects the endpoint; the specific transport is chosen
per task by a protocol byte (6 = TCP, 17 = UDP). The whole thing is implemented as
polymorphic method classes, not a `switch`.

## What the scanner looks like on the wire

The scan engine writes fixed, fingerprintable fields:

| Marker | Value | Tag |
|---|---|---|
| SYN source port | 19000 | CORROBORATED |
| SYN ISN | seed `0x3251d2d`, +1 per target | NOVEL |
| ICMP echo id | 19037 (`0x4a5d`) | CORROBORATED |
| ICMP echo sequence | 36765 (`0x8f9d`) | NOVEL |

The detail that matters for detection is the **ISN**. A normal OS randomizes the initial
sequence number per connection; JDY uses a fixed low seed and a per-target counter. The
receive validator confirms a SYN-ACK by checking `reply_ack == sent_seq + 1`. The durable
selector is therefore **source port 19000 plus an ascending ISN run seeded at `0x3251d2d`**
— not source port 19000 alone, which overlaps Mirai-class and SSH brute-force noise. Only
the first SYN of a batch carries the seed value exactly; the rest climb from it.

## Central tasking updates: the dmap mechanism

The implant supports an `update_dmap_fp_db` command that maintains a fingerprint database
the fleet uses to recognize services. It builds `/dispatch/v2/dmap/<digest>` and downloads
the archive, and the fetch is **digest-gated** — the bot only re-downloads when the
published digest changes. This is the delivery path that lets operators update what the
fleet recognizes and targets without redeploying implants, and it is the mechanical enabler
of JDY's rapid-CVE pivoting. The **mechanism** is confirmed; the **record format** of the
archive remains open, pending a captured archive.

## The dispatch API surface

Beyond the published tasking URI, the implant's strings expose the full API, including
endpoints not present in prior public reporting:

| Endpoint | Role | Tag |
|---|---|---|
| `POST /dispatch_service/v2/probe_task` | Pull encrypted tasking | PUBLISHED |
| `POST /dispatch_service/v2/probe_status` | Submit scan results / status | **NOVEL** |
| `POST /dispatch_service/v2/test` | Liveness stub (returns `{"code": 200}`) | **NOVEL** |
| `/dispatch/v2/dmap/<digest>` | Fingerprint-DB fetch | CORROBORATED |
| `/data/v2/pscan`, `/wscan` | Strategy endpoints | CORROBORATED |

The dispatch tier was fingerprinted from packet captures: an **nginx** front-end
reverse-proxying a Python **Django (DRF)** backend. The Django identification came from the
server's HTTP 500 body — Django's signature default HTML, where a FastAPI/Starlette backend
would return JSON — plus a `Vary: Cookie` header. The nginx version differs per node, so the
web-stack version is never a cluster-wide selector.

## Being wrong on purpose

Treating AI-assisted output as leads to reproduce, rather than findings to accept, is the
methodology that earned its keep here. Several headline claims were reversed on the bench,
each by primary evidence:

- **`meth_tunnel` is a client connect-out, not a SOCKS relay or ORB pivot.** The implant has
  no `listen` and no `accept` (the only `accept` resolves to libc); the transport holds one
  socket descriptor and handles the non-blocking outbound-connect idiom (`EINPROGRESS` /
  `EAGAIN`). It connects out; it does not accept. The `"tunnel"` string that suggested a
  relay is a JSON field name.
- **`headmap` / `archmapped` are glibc internals, not the dmap format.** These `mmap`
  assertions were associated with the dmap archive by the shared keyword "mmap." Following
  the references shows they belong to a glibc dlsym-style symbol-hash lookup that the dmap
  handler never reaches.
- **The backend is Django, not FastAPI.** Settled by the 500-body signature in the captures.
- **The ICMP sequence is 36765, not the published 35765.** This sample loads `0x8f9d`;
  `0x8bb5` is not present anywhere in the binary. 36765 is authoritative for this sample; the
  published value differs by exactly 1,000 and is assessed as a different build or variant.

A clean reversal backed by primary evidence is stronger intelligence than an unchecked
assertion. The full corrections log is in the repo.

## Rapid-CVE pivoting, and a disambiguation

JDY's defining operational behavior is speed: it scans for newly disclosed vulnerabilities
within hours of disclosure. FortiClient EMS **CVE-2026-35616** was scanned for within hours
of going public. The dmap mechanism is what makes this possible at fleet scale.

One disambiguation matters. JDY **scans** for CVE-2026-35616; it does **not** exploit it.
The public exploitation campaign on that CVE — the EKZ Infostealer delivered to Windows
hosts — is a **separate criminal actor** sharing interest in the same CVE. Same-CVE
coincidence, not shared tooling. Conflating the two would invent a delivery chain that does
not exist (**EXCLUDED** as JDY).

## The infrastructure finding is an absence

The control cluster is anchored by a single durable artifact: the **jdyfj self-signed
certificate** (SHA-256 `2b640582…432cf`, serial `0xab8f51eb48f363f1`, CN=jdyfj, SAN=1.2.3.4,
RSA-4096, valid to 2033-11-11). The same 4096-bit keypair is reused across relays, and that
reuse is what let the cluster be enumerated at all. It was triple-confirmed across FOFA,
Netlas, and Shodan and re-confirmed in packet capture.

Everything else resisted pivoting. Six independent hunts — the certificate and TLS-fingerprint
pivots, a 3X-UI management panel, a fronting domain, the malware-relationship graph, the
payload-host service profile, and a build-path search — **all bottomed out in commodity
infrastructure**. The relays are vanilla rented VPS nodes across providers like Evoxt, M247,
and BrainStorm; a separate Vultr host serves as the payload tier. Their SSH host keys are
**unique per box** (a key-blob search returns one result each) and their nginx versions
differ, which together prove the nodes were provisioned independently rather than cloned.
They are findable individually but unlinkable to one another in public data.

That convergence is the intelligence product. JDY's control layer is **deliberately
atomized**: the relays are expendable and rotatable by design, because the actor's stealth
lives victim-side — living-off-the-land on the compromised edge device — not in the relay it
talks to. **The absence of a pivotable cluster is itself the finding**, consistent with Volt
Typhoon prepositioning doctrine. There is no single thread that unravels the network, and
that was demonstrated six different ways rather than asserted once.

## When a selector returns thousands, it's noise

A practical corollary for anyone hunting this actor: a real JDY selector returns a handful of
hosts; a commodity one returns thousands. The population size is the tell. The selectors that
looked promising and collapsed:

| Selector | False-positive population |
|---|---|
| Cover-page body hash | 63,870 |
| 3X-UI panel CSS fingerprint | 88,452 |
| Bare JARM on a common nginx stack | 63,870 |
| Acme Co cert + ports 9960-9964 | 2,369 |
| Platypus :13339 alone | 313 |
| Source port 19000 alone | Mirai / SSH-brute noise |

The payload host illustrates the discipline: Platypus on `:13339` alone and the Acme Co
Go-TLS block on `:9960-9964` alone are each commodity, but the **pairing** of the two on one
host is singular. The promotion rule that fell out of this: a candidate host is JDY-relevant
only if it carries the jdyfj certificate or the paired payload-host profile, verified against
stored scan data. Adjacency, a shared provider, or any single common selector is not
promotion.

A behavioral-cataloging hunt confirmed the same lesson from the other side. A GreyNoise sweep
on source port 19000 returned thousands of IPs; the residential candidates triaged by hand
were all Mirai-class or SSH brute-forcers. JDY's quiet SYN recon is simply not separable by
loud-scanner cataloging — the right instrument is the seeded-ISN signature, not the port.

## What was novel

| Finding | Tag |
|---|---|
| Tasking is AES-128-CBC; published key is IV ∥ KEY, not AES-256 | NOVEL |
| Key `bdb718bdf47cbcde` (16 ASCII bytes, raw), IV `0x30` × 16 | NOVEL |
| Dispatch endpoints `/probe_status` and `/test` | NOVEL |
| Build path `/usr/local/openssl/1.0.2u/mips64/` (nested form) | NOVEL |
| SYN ISN seed `0x3251d2d`; ICMP sequence 36765 | NOVEL |
| Backend is Django (DRF) behind nginx | CORROBORATED |
| dmap fingerprint-DB mechanism (digest-gated) | NOVEL (mechanism) |

## What's still open

No investigation closes clean. The honest gaps:

- **dmap record format** — the mechanism is confirmed, but the archive structure is unmapped
  and needs a captured archive.
- **A live `probe_task` ciphertext** — the decryptor is validated by inline-scheme
  confirmation and offline round-trip; a real captured blob would add the final increment of
  confidence.
- **The ICMP-sequence variant** — 36765 is authoritative for this sample; the published 35765
  variant is unconfirmed against a second sample.
- **Sibling samples** — none surfaced on public platforms; a build-path corpus retrohunt is
  the remaining untried discovery path.

## Defensive takeaways

For defenders, the durable advice is not an IP blocklist — the relay layer rotates by design.
It is:

- **Reduce edge exposure.** Inventory and harden every internet-facing router, firewall, VPN
  concentrator, and IoT device. Retire end-of-life gear; it is the actor's preferred real
  estate.
- **Compress patch latency on perimeter devices to days, not weeks.** The scan-to-CVE window
  is hours.
- **Watch egress.** The detectable signal is outbound — beaconing to commodity VPS relays and
  the seeded-ISN scan profile. Anchor detections on the jdyfj certificate and the behavioral
  signature, not on the rotating IPs.
- **Pair your selectors.** Anything that isn't the cert or the paired payload-host profile
  needs a second discriminator, or it will bury you in commodity false positives.

Sigma rules, a YARA clustering rule, an incident-response playbook, a threat-hunting guide,
and the full IOC set are in the repository.

## Method and provenance

This was a defensive, passive-OSINT analysis of an already-public sample and its publicly
observable infrastructure, intended to build detections and inform defenders. AI-assisted
output was treated as leads and reproduced in Ghidra or against primary scan data before
acceptance; several headline claims were reversed on the bench and are documented in the
corrections log. One engagement was re-scoped to passive after initial contact; no further
active interaction occurred.

Full package — RE write-up, three-tier intelligence reports, detections, IOCs, and the
decryptor:
[github.com/yankywilson/jdy-botnet-threat-analysis](https://github.com/yankywilson/jdy-botnet-threat-analysis/tree/main).
