---
layout: post
title: "ShinySp1d3r: Anatomy of a Ransomware-as-a-Service Build System"
date: 2026-07-15
categories: [threat-intelligence, malware-analysis]
tags: [shinysp1d3r, sh1nysp1d3r, scattered-spider, scattered-lapsus-hunters, shinyhunters, ransomware, reverse-engineering, golang, screenconnect, meshcentral, yara, sigma, detection-engineering, icd-203]
---

ShinySp1d3r is a Windows ransomware family assessed likely operated by the Scattered
Spider-aligned Scattered LAPSUS$ Hunters cluster. This is a technical analysis of two
affiliate builds and a live rogue remote-management estate, published while the family
remains pre-deployment -- the only period in a ransomware family's lifecycle in which
defenders are ahead of it. It covers a seventeen-field configuration structure that makes
the RaaS model legible, five constructs in the binary that read as active and are not, and
an instrument register of the queries that lie.

<!--more-->

**Technical Analysis of a Pre-Deployment Encryptor and Its Operator Infrastructure**

*Analysis conducted against samples recovered from public repositories. Estimative language
follows ICD-203; likelihood and confidence are stated separately throughout.*

---

## Executive Summary

ShinySp1d3r is a Windows ransomware family assessed likely operated by the Scattered
Spider–aligned Scattered LAPSUS$ Hunters cluster (low confidence; attribution held per
public reporting, not independently corroborated by the primary data underlying this
report).

This report documents sixty-three reverse engineering findings across two affiliate builds,
a live rogue remote-management estate associated with the same ecosystem, and the detection
content derived from both. It is published while the family remains **pre-deployment**.

That timing is the point. At the date of writing there are no publicly confirmed
ShinySp1d3r victim environments. The samples analysed here are in-development builds. A
ransomware family with no deployments has no incident data — but it has a binary, and the
binary is fully readable. The module architecture, the configuration structure, the
container format and the cryptographic chain are all knowable now, before the first victim.
This is the only period in a ransomware family's lifecycle in which defenders are ahead of
it.

Three findings drive everything else.

**First, ShinySp1d3r is a build system, not a tool.** A seventeen-field configuration
structure — every field settable at compile time — governs behaviour, and the source
filename embedded in the symbol table is `main_generated.go`. The developer ships
capability; the affiliate configures a campaign. The defaults are instructive: impact
behaviours ship enabled, network propagation ships disabled. A default build encrypts the
host it lands on and nothing else.

**Second, the binary contains five constructs that read as active and are not.** Three of
them are properties of how Go binaries are built rather than anything specific to this
family, and will catch any analyst working from a symbol dump or a string extraction.
Documenting them, and the cross-reference method that separates presence from execution, is
the most transferable material in this report.

**Third, the ransomware half and the infrastructure half of this investigation have never
been joined by primary evidence.** Both inherit their actor identity from the same
third-party reporting. That seam is stated openly in this report rather than papered over,
because a reader deciding how much weight to place on the attribution needs to know what
carries it.

---

## Key Findings

| Finding | Assessment |
|---|---|
| Ransomware-as-a-Service build system, not a standalone tool | **Almost certain / High confidence** |
| Encryptor is C2-less by design — no external command and control | **Almost certain / High confidence** |
| Two known samples are affiliate builds of one template | **Almost certain / High confidence** |
| File encryption is **unauthenticated ChaCha20** — no Poly1305, no integrity tag | **Almost certain / High confidence** |
| Key wrapping is **RSA-OAEP**, 2048-bit; the modulus spans both builds | **Almost certain / High confidence** |
| **ML-KEM-768 is compiled in and dormant** — victim files are not post-quantum protected | **Almost certain / High confidence** |
| Encrypted-file extensions are drawn at random from a closed 62-member set | **Almost certain / High confidence** |
| Operated by the Scattered Spider–aligned SLSH cluster | **Likely / Low confidence** |
| The rogue RMM estate and the ransomware are one operation | **Likely / Low confidence** |
| The estate delivers ShinySp1d3r specifically | **Roughly even chance / Low confidence** |

Likelihood and confidence are separate axes and are stated separately throughout. *Likely*
at low confidence means the proposition is more probable than not on the evidence available,
and the evidence available is thin. Both statements are true at once; collapsing them into a
single number discards what a reader needs.

---

## Samples

| | Packed | Unpacked |
|---|---|---|
| SHA256 | `3bf53cddf7eb98d9cb94f9aa9f36c211a464e2c1b278f091d6026003050281de` | `670a269d935f1586d4f0e5bed685d15a38e6fa790f763e6ed5c9fdd72dce3cf2` |
| MD5 | `60f0d614ee1cfcfd237f6705a33765c3` | `2b3875b6b7913a5a61e2acccb4fb8ca9` |
| Size | 4,677,224 bytes | — |
| Mutex prefix | `Google\` + 7 characters | `Global\` + 8 characters |

Both are Go 1.24.5, PE32+ x64, `CGO_ENABLED=0`, entry point `0x47a600`, with a zeroed
compile timestamp.

The mutex prefix differs between builds. The RSA modulus and the ransom-note template do
not. Any signature anchored on a build's mutex prefix will not fire on the other; signatures
anchored on the operator key or the internal module paths fire on both. This distinction
matters more than it appears — it is the difference between a rule that covers a family and
a rule that covers one affiliate.

---

## The Build System

The strongest evidence for the business model is in the binary, and it is primary.

A flat structure at `0x00852440` carries seventeen fields:

| Address | Field | Default |
|---|---|---|
| `0x0085244b` | `EnableETW` | **true** |
| `0x0085244c` | `Debug` | false |
| `0x00852441` | `DeleteEventLogs` | **true** |
| `0x00852442` | `ChangeWallpaper` | **true** |
| `0x00852443` | `SingleInstance` | **true** |
| `0x00852444` | `LocalEncrypt` | **true** |
| `0x00852446` | `KillServices` | **true** |
| `0x00852448` | `Propagate` | **false** |
| `0x0085244a` | `FreeSpaceCleaner` | **false** |
| `0x00852449` | `SelfDestruct` | **true** |
| `0x00852450` | `EncryptionMode` | string |
| `0x00852460` | `Credentials` | string |
| `0x00852470`–`0x00852474` | `UseWMI` · `UseSCM` · `UseGPO` · `UseNetShares` · `UsePSExec` | all **false** |

Two slots in the array — `0x00852445` and `0x00852447` — were not mapped and are recorded
as a gap.

The division is the finding. Everything that produces impact ships on. Everything that
spreads ships off, and requires an affiliate to enable it and supply credentials as a
build-time overlay. Taken with `main_generated.go` — the binary is template output, not
hand-written per victim — the reading is unambiguous.

This has a counter-intuitive detection consequence that is easy to get backwards. **A rule
tuned to propagation artifacts, or to partial-encryption artifacts, assumes an affiliate
configured them.** Under default configuration those rules see nothing. The behaviours that
always fire are the impact behaviours — which are also the last to fire.

Credentials warrant precision because they are frequently misdescribed. In the samples
examined, credentials are a **build-time configuration string**, consumed via `LogonUserW`
inside the propagation modules. There is no `os.Args` handling and no flag parsing anywhere
in the execution path. The binary states the behaviour itself:

```
[Propagation] No credentials provided, using current user context
[Share Access] Will attempt with %d additional credential(s)
```

Credentials are optional and additive. Absent them, propagation runs under the token the
process already holds.

**This finding is scoped to the samples examined.** Public reporting quotes the developers
stating that a command-line build with runtime configuration has been completed. No such
build has been observed in this analysis. *This sample takes no command-line configuration*
is supported. *This family takes no command-line configuration* is not.

---

## Execution Chain

Reconstructed from embedded log strings and decompiler output. Stage boundaries are the
binary's own.

**Stage 1 — Initialisation.** API resolution by hash through an internal `apihash` module,
loading kernel32, ntdll, advapi32, user32, shell32, psapi and tlhelp32. **No network DLL is
resolved** — no ws2_32, no winhttp, no wininet. That absence is structural evidence, not an
oversight. ETW evasion follows, hooking `EtwEventWrite` **system-wide, in every running
process**. A `hookshield` module then runs a continuous loop that re-applies hooks if an EDR
restores them, writing hook state to a file named `restored_hooks`.

**Stage 2 — Environment checks.**

```
Check: domain membership     -> skips AD enumeration if not in a domain
Check: domain admin token    -> skips GPO deployment if not satisfied
```

These are branches, not gates. The binary skips a propagation vector when a check fails; it
does not halt. The privilege check is three-tier and inspects the token the process already
holds:

```c
OpenProcessToken(current_process, TOKEN_QUERY, &token)   // fallback: OpenThreadToken
hasTokenElevation(token)
getTokenGroups(self)                     // SID enum: -512 Domain Admins, -519 Enterprise Admins
sidToString(SID) == "S-1-5-32-544"       // hardcoded BUILTIN\Administrators fallback
```

The third tier is the one that matters. **`BUILTIN\Administrators` satisfies the check.**
Local administrator on any domain-joined host is sufficient; explicit Domain Admin is not
required. The gate is considerably wider than its SID enumeration suggests.

**One dynamic-analysis gap is recorded openly.** In sandbox analysis with no domain present,
execution halted at this stage and `WerFault.exe` fired. That is a domain-membership
dependency, not a Domain Admin requirement for encryption — static analysis establishes that
`LocalEncrypt` defaults true and `Propagate` defaults false, so a default build encrypts
locally with no domain involvement at all. Whether the binary proceeds past this stage in a
domain-joined environment **was not tested**. A patch-and-detonate procedure was scoped and
not executed. The claim *"it will not run without Domain Admin"* is not supported by any
evidence in this analysis, and the claim *"it runs regardless"* is not established either.

**Stage 3 — Preparation.** Shadow copy deletion via dual method — WMIC command line and
direct WMI query. Process and service termination, 31 targets. Windows event log clearing.
File-lock handle termination.

**Stage 4 — Local encryption.** Unconditional on privilege. Mode is config-driven, not
size-driven.

**Stage 5 — Impact.** Ransom note per directory as `R3ADME_[8chars].txt`. Wallpaper set from
an obfuscated blob. Free-space wiping if enabled.

**Stage 6 — Lateral movement.** Governed by `Propagate`, false by default. Five vectors. AD
enumeration is dual-method — LDAP via ADSI and NetAPI. **GPO deployment targets
`{31B2F340-016D-11D2-945F-00C04FB984F9}` — the Default Domain Policy, hardcoded.** Not an
arbitrary GPO. Maximum blast radius by design.

**Stage 7 — Self-destruct.** True by default. Three methods: `DELETE_ON_CLOSE`, WMI, and
reboot-scheduled deletion. The VBS path drops a WMI re-query loop that waits for the process
to exit, deletes the binary and quits.

Stages 1 through 3 all complete before the first file is touched. That is the detection
window, and it is the only one that exists for this family.

---

## Cryptography

| Component | Implementation |
|---|---|
| File cipher | **ChaCha20, unauthenticated** — `chacha20.NewUnauthenticatedCipher` |
| Session key | 32 bytes from `crypto/rand`, **per file** |
| Nonce | 12 bytes from `crypto/rand`, per file |
| Key wrapping | **RSA-OAEP**, 2048-bit |
| Memory protection | `mlock` equivalent against swap; zeroed on function exit via `defer` |
| Post-quantum | **None. ML-KEM-768 is compiled in and dormant.** |

Partial encryption is not a second algorithm. It is ChaCha20 keystream seeking:

```c
SetCounter(offset / 0x40)              // seek to block: file_offset / 64
XORKeyStream(dummy, dummy, offset % 64) // burn the prefix
XORKeyStream(dst, src)                  // encrypt the chunk
```

ChaCha20's 64-byte block structure makes arbitrary seeking cheap. Both modes execute
identical code; only the byte ranges passed in differ. One keystream covers the whole file.

The encrypted byte ranges are selected by
`generatePartialEncryptionOffsets(file_size, SHA256(path + 8_null_bytes + session_key))` —
deterministic given the session key, unreproducible without it.

**Assessment: the key management is competent.** Per-file random session keys, a 2048-bit
RSA-OAEP wrap, no key reuse, no static wallet, no fallback key, locked and zeroed memory.
There is no cryptographic weakness to attack. Encrypted contents are recoverable only with
the operator's private key.

**The absence of Poly1305 is a design choice with forensic consequences rather than a
weakness in the encryption.** There is no authentication tag on encrypted output. Modified
or partially reconstructed ciphertext produces no detectable failure.

### The operator key

The RSA-2048 modulus is embedded in `.rdata` at raw offset `0x00252BF2`, with a single
cross-reference from `main.encryptFile`. It spans **both** known affiliate builds, which
makes it a campaign fingerprint rather than a build fingerprint — and therefore the correct
pivot for locating siblings.

**It is stored as 512 ASCII hex characters, not 256 raw bytes.** The arithmetic is the
proof: a 2048-bit modulus is 256 bytes; the field is 512. What sits at that offset is the
character sequence `A`, `E`, `C`, `F` — bytes `41 45 43 46` — not the bytes `AE CF DF 18`.

This has an operational consequence that is easy to miss. **A signature built from the
decoded modulus does not match the file.** The decoded form exists only after
`encoding/hex.DecodeString` runs at runtime. This is not an anomaly; it is how the binary
stores everything. The ransom wallpaper is a hex-encoded blob decoded through the same path,
and an internal shares module uses the identical scheme.

---

## The Container Format

Every encrypted file is rewritten as an `SPDR` container. The format is identical across
file types — encryption is format-agnostic.

```
Offset      Size        Field
----------  ----------  --------------------------------------------------------
0x000       4           "SPDR"                     magic
0x004       2           flags        uint16 BE     1 = full, 2 = partial
0x006       2           uint16 BE
0x008       1           uint8
0x009       4           RSA-key-len  uint32 BE     observed 256
0x00D       variable    RSA-OAEP wrapped ChaCha20 session key
+           12          nonce
+           1           uint8
+           4+32        [PARTIAL MODE ONLY] uint32 + SHA256
+           4           path-len     uint32 BE
+           variable    original file path         CLEARTEXT
+           8           original file size  uint64
+           4           "ENDS"                     footer magic
+           remainder   ciphertext
```

Thresholds are `0x500000` (5 MiB) and `0x63FFFFF` (100 MiB − 1), from
`main.decideEncryptionMode` at `./main_generated.go:643`.

**100 MiB is unusually high.** LockBit partial-encrypts above 2 MiB; Conti above 5 MiB. This
family fully encrypts substantially more of a victim estate before partial mode engages —
and the mode is config-driven regardless, so an affiliate can force partial at any size or
leave the default and encrypt everything fully.

---

## Five Analytical Traps

A Go binary's symbol table lists what the linker included, not what the malware calls. A
string in a memory dump proves bytes exist somewhere in the process, not that the code path
producing them ever ran. A byte sequence constant across every collected sample is constant
across those samples, not necessarily by construction.

This binary contains five constructs that read as active and are not. All five are
recoverable with a cross-reference walk in any decompiler. The point is that the walk is not
optional.

### Trap 1 — `chacha20poly1305` is linked. Nothing calls it.

The symbol table contains `golang.org/x/crypto/chacha20poly1305`. AES-CBC and AES-CTR are
also present as Go 1.24.5 FIPS stdlib dependencies. A string extraction returns all of them.
The natural inference — authenticated encryption, possibly with an AES path — is wrong on
both counts. `NewUnauthenticatedCipher` is a different constructor from the AEAD interface,
and it is what every file goes through.

Public reporting describes the cipher as ChaCha20, which is accurate. The finer question —
whether the construction is authenticated — is what has forensic consequences.

### Trap 2 — `RSASSA-PKCS-v1.5` is in the binary. It is the fake signature, not the crypto.

A memory dump yields the string `RSASSA-PKCS-v1.5 2048-bit sign and verify`. Read alone, it
says the malware wraps session keys with PKCS#1 v1.5 padding. It does not. **That string
belongs to the fake Authenticode overlay** — a crafted, truncated PKCS#7 structure carrying
no certificates, appended to impersonate a signed executable. The overlay describes a
*signature* scheme. The key-wrapping path calls `crypto/rsa.EncryptOAEP` and never touches
it.

This is the most instructive of the five. The trap is not linker baggage — it is a decoy
artifact whose metadata reads like a description of the malware's cryptography.
**Anti-analysis features generate strings too, and those strings describe the anti-analysis
feature.**

### Trap 3 — ML-KEM-768 is compiled in. It is dormant.

Go 1.24.5 ships `crypto/internal/fips140/mlkem` in the standard library. Its type signatures
are present. A symbol dump makes the family look post-quantum.

Walking incoming references to the primitive returns exactly two callers — `kemEncaps` and
`kemDecaps` — both **internal to the ML-KEM algorithm itself**. That is the algorithm's own
structure and proves nothing. Zero callers reach it from `main` or from any internal module.

**A package calling itself is not evidence of use.** The question is always whether anything
*outside* the package reaches in.

### Trap 4 — The container's "constant" block is four fields.

Every encrypted file opens with the same thirteen bytes: `53 50 44 52` followed by nine that
do not vary. The natural reading is a version/flags block, constant by construction — and
downstream of that, a fixed 256-byte key field and a fixed 16-byte IV, landing the cleartext
path at a fixed offset.

The nine bytes are four big-endian fields: a mode flag, two reserved values, and an RSA key
length. They were constant across the collected samples because every sample was full-mode
with a 256-byte key.

**Partial-mode files carry `00 02` at offset `0x004`.** Any signature hardcoding the nine
bytes silently misses every file above the 100 MiB threshold — the databases and disk
images. Testing confirms it: against synthetic containers, a hardcoded header matched one of
four cases; a wildcarded mode byte matched all four.

What appeared to be a 16-byte IV was a 12-byte nonce plus a `uint8` plus three high-order
zero bytes of a big-endian length field. What appeared to be a one-byte path length was that
field's low-order byte — correct for every path shorter than 256 characters, which is every
path anyone sampled.

**Both readings measured real bytes correctly.** The coarse reading is right about this
build and wrong about the format.

### Trap 5 — Count the constant, not the extraction.

Memory analysis recovered 29 process-kill targets. The binary carries the count:
`DAT_008506e8 = 0x1f = 31`.

Static extraction over `.rodata` recovered 30. The thirty-first is `sql` — three bytes, at
`0x0063c09a`, below the threshold of the earlier extraction. It matches any process name
containing the substring, which takes `sqlservr`, `sqlwriter`, `sqlagent` and `sqlbrowser`
in a single entry.

**The 3-byte target is the highest-impact entry in the list and it is the one an extraction
threshold discards.** The earlier list also contained two entries absent from `.rodata` —
memory dumps contain strings from every process in the snapshot, and membership in a dump is
not membership in a table.

### The method

**Recover symbols, then never treat presence as reachability.** Go links what the import
graph pulls in, transitively, whether or not any of it executes. For a cryptographic
construct the only question that matters is whether malware code reaches it.

**Walk incoming references until landing somewhere that matters** — `main`, an internal
module, or out of callers. Landing only in the construct's own package is the dormant
signature.

**Attribute strings to the artifact that produced them.** Ask what component a string
belongs to before asking what it implies.

**Prefer the binary's own constants to measurements.** Where a field looks constant, check
whether it is constant by construction or constant across the sample. The two are not the
same.

---

## Operator Infrastructure

A rogue ScreenConnect and MeshCentral estate associated with the same ecosystem was mapped
across a twelve-month window. Both platforms are legitimate commercial remote-management
tools in daily use by legitimate MSPs and IT departments; what follows concerns rogue
deployments of them.

| | |
|---|---|
| `80.76.49.99` | ScreenConnect Host panel, port 8040. **Confirmed live 14 July 2026** by behavioral packet capture — a third party's sample beaconed and received `200 OK`. Domain `services-server0-web.com`, registered 28 June 2026. **0/91 detections.** |
| `80.76.49.91` | **Also live.** RDP observed 14 July 2026 17:04 UTC. A ≥12-month host that sequentially carried Tactical RMM on `:443`, MeshCentral on `:4433`, and a ScreenConnect relay on `:8041`. |
| Build | Stock ScreenConnect 25.2.4.9229, DarkTeal theme, no custom branding |
| MeshCentral | Self-signed per-instance root `MeshCentralRoot-c9a7aa` |

### The estate is joined by a certificate, not by an ASN

`80.76.49.91:4433` served a leaf certificate naming `mesh.upohelp.top` in its Subject, its
DNS SAN, and its URI extension. The Subject Public Key Info hash was **derived from the
certificate's raw modulus** and validated against the certificate's own Subject Key
Identifier:

| Check | Result |
|---|---|
| SHA-1 over the reconstructed public-key DER must equal the certificate's own SKI (RFC 5280) | computed `e38dafed967046d80b529659fb82b8117c6a2adc` — the certificate says the same |
| Therefore SHA-256 over the same structure is authoritative | `865e2ba7e935e28a646dd8bd19400cad24ea3423f06936ed633b9721d22f41fa` |

**If the DER construction were wrong, the SHA-1 would not have reproduced the certificate's
own SKI. It did.** The encoding validates itself.

This distinction is load-bearing. Concluding *"both hosts are on the same ASN, therefore
same actor"* would be address adjacency. **A certificate that names a domain in its own
Subject, served from an estate IP, is identity of instrument.** The domain is *in* the
certificate.

| Proposition | Likelihood | Confidence |
|---|---|---|
| The certificate on `.91:4433` is the `mesh.upohelp.top` leaf | Almost certain | High |
| The MeshCentral cluster and the ScreenConnect estate are one operator's estate | Almost certain | **Moderate** — the certificate is double-sourced; **the serving observation is single-engine** |

The confidence is held at Moderate deliberately. Two major scanning engines never indexed
port 4433 on this host. That is the reason for the caveat, and it is a finding in its own
right.

### Shared infrastructure is not shared identity

The same ASN hosts `sptcadmin.com` on a separate netblock — a **different, unrelated**
rogue-ScreenConnect operator, distinguished by different build GUIDs, a different port
deployment, and a different network. Two rogue RMM operators, one ASN, no relationship.

**No ASN-wide block appears in the accompanying detection content, and none should be
applied.** Bulletproof and low-diligence hosting concentrates unrelated criminal activity by
construction. Presence is not association.

---

## Instrument Failures

Roughly half the null results produced during this investigation were **instrument** nulls,
not intelligence nulls. That distinction is not pedantry. A null from an instrument that
could never have returned a positive reads identically to a null from an instrument that
looked and found nothing — and one of them is a finding while the other is noise.

**Two rules were derived from specific failures, both with worked examples.**

**Run the positive control first.** Every fingerprint sweep must first return the
known-positive host. If the instrument cannot see the host already known to carry the
artifact, its null is an instrument result. In this investigation the control caught a
broken date filter that would have entered the record as *"no siblings before July"*, and it
invalidated five sweeps whose engine had never crawled the port carrying the artifact.

**A null is per-engine and per-window, never per-internet.** One engine indexed the
MeshCentral certificate on port 4433. Two others never crawled it. Both returned null on a
value that was **correct**, against a host that **was serving it** — and that null was
written up as *"expected, the instance is behind a CDN."* It was not behind a CDN. It was
the origin. **The wrong diagnosis suppressed a real finding for a full session.**

**Measured base rates matter more than instinct.** Fingerprints that appear operator-specific
frequently are not:

| Value | Measured |
|---|---|
| JA3S on the MeshCentral port | **225,691,497 hits** |
| JARM on the ScreenConnect panel | **20,016 hits** — Windows Schannel TLS stack |
| ScreenConnect build GUIDs | **Deterministic per build, not per operator** |

The JARM and JA3S values were previously carried as durable hunting pivots. They are not
pivots; they are the TLS stack. They are published in the accompanying repository
specifically so that nobody else spends a session on them.

The build GUIDs are worth a note of their own. **They are deterministic per ScreenConnect
version — two stock installs of the same build share all five.** A match means "same
version," not "same actor." They earn their place because of what they *excluded*: they are
what proved the unrelated operator on the same ASN was unrelated. **Trust them to kill, not
to confirm.**

---

## The Seam

Two bodies of primary analysis are published together here. **They are not joined by primary
evidence.**

The ransomware analysis and the infrastructure analysis are each independently strong. Both
inherit the actor identity from the same external source. No sample analysed was retrieved
from the estate; no indicator from the estate appears in any sample.

The encryptor is **C2-less by cross-reference proof** — the only internal functions reaching
`net.(*Dialer).DialContext` are a share-port check and a subnet scanner, both internal
lateral movement, and no internal caller reaches `net/http.(*Client).Do`. **A C2-less
encryptor cannot be linked to infrastructure by its own traffic.** That is a property of the
target, not a collection failure.

With no confirmed victims anywhere, there is no environment in which the two halves could
have been observed together. **The seam may be unclosable with current collection rather
than merely unclosed.**

The certificate join documented above moved infrastructure to infrastructure. **It did not
touch the seam.** Both halves of that join sit on the same side of it.

What would close it: a sample retrieved from the estate; an estate host bearing encryptor
artifacts; a victim environment containing both; shared build GUIDs, certificates or keys
across the two halves. None is held. The last was searched for and not found.

**Everything in this report assessed at high confidence is a property of a binary or an
estate and holds regardless of attribution.** Everything carrying the actor label is low
confidence, for one reason: the seam.

---

## Detection

Accompanying content: **9 YARA rules, 36 Sigma rules, 18 KQL queries, 7 Suricata rules, Zeek
scripts.** All are untested against live telemetry; the findings underneath them are
verified.

**Where to deploy first:**

| | Rule | Why |
|---|---|---|
| **1** | Dual-RMM co-occurrence | Access stage. Two unauthorised remote-management agents on one host, neither matching the authorised estate. Low base rate, weeks of lead time. |
| **2** | Module architecture | Survives recompile — Go embeds package paths in the symbol table, so evasion requires renaming every module. |
| **3** | RSA key, offset-anchored | 40 ASCII characters at a fixed raw offset. Near-zero false-positive surface. |
| **4** | Impact-stage rules | Alert late by construction. Deploy them; do not rely on them. |

**Three implementation notes carry more weight than the rules themselves:**

**The RSA key is ASCII hex text.** A signature built from the decoded modulus matches
nothing.

**Do not hardcode the bytes following the container magic.** They encode mode and key
length. Hardcoding them matches full-mode files only and misses everything above 100 MiB.

**Populate the legitimate-tooling filter in every Sigma rule before deployment**, or the
rules will alert on authorised administrators.

---

## Incident Response

**If encryption is in progress, capture memory before anything else.** Session keys are
locked against swap and zeroed when the encryption function returns. A capture taken *during*
encryption has them; a capture taken after does not. That window closes and does not reopen.

**Do not reboot** — reboot-scheduled deletion is one of three self-destruct methods. **Do
not kill the process** — self-destruct defaults on, and terminating the process may complete
its cleanup. Isolate at the network layer.

**Scope recovery precisely.** A blanket *"nothing is recoverable"* is wrong and costs data:

| | |
|---|---|
| Full-mode contents | **Not recoverable.** No path without the operator's private key. |
| **Partial-mode contents (≥100 MiB)** | **Substantially intact** — selected ranges only. **Check the header byte at `0x005` before writing off a large file.** A 500 GB disk image in partial mode is not a 500 GB loss. |
| Free space | Wiping defaults **off**. Absent `wipe-*.tmp` artifacts, unallocated space is intact. |

**The per-build Case ID is a correlation instrument across incidents.** Two victims
presenting the same value were hit by the same affiliate build — which works where nothing
else is shared.

**One tripwire is worth monitoring.** The ransom note's `.onion` field carries a placeholder
where the leak-site address belongs. **The moment that field is populated in a sample, the
family has moved from development to deployment.**

---

## Assessment

ShinySp1d3r is competently built. The cryptography has no weakness to attack. The
anti-analysis stack is layered and system-wide. The configuration structure is the work of
developers building a product rather than operators building a tool, and the defaults
indicate an affiliate model already designed rather than improvised.

It is also, at the time of writing, **undeployed** — and that is the entire opportunity. A
family with no victims has no incident data, but it has a binary, and the binary answers
every question a defender needs to ask before the first intrusion rather than after it.

The traps documented here are the most transferable finding. They are not specific to this
family: any Go binary with a FIPS standard library and an anti-analysis overlay will present
the same three constructs to the same string extraction and produce the same three wrong
conclusions. **The cross-reference walk that separates them costs minutes and is not
optional.**

The seam remains open and is stated as such. It may not close.

---

## Availability

Full findings, indicators, detection content, methodology and the instrument register are
published in the accompanying repository: **[shinysp1d3r-intel](https://github.com/yankywilson/shinysp1d3r-intel)**. Indicators are tiered by durability and
date-stamped. **Atomic indicators are perishable** — infrastructure confirmed live on 14 July
2026 may be dead, re-registered, or reassigned to an unrelated party by the time this is
read.

Published for defensive use. Detection content is provided as-is and untested against live
telemetry; validate in your environment before deployment.
