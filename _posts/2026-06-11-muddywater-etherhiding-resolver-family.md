---
layout: post
title: "Inverting the Bulletproof: How MuddyWater's EtherHiding C2 Became One Smart Contract Too Many"
subtitle: "An independent on-chain investigation that turned a single disclosed Ethereum contract into a seven-contract MuddyWater command-and-control family — and a durable detection anchor that survives every IP rotation."
date: 2026-06-11
author: Yanky Wilson
categories: [threat-intelligence, malware-analysis]
tags: [muddywater, seedworm, iran, mois, etherhiding, tsundere, blockchain-c2, ethereum, mitre-attack, detection-engineering, osint]
description: "MuddyWater adopted EtherHiding for blockchain-based C2. Public reporting found one contract. On-chain analysis reveals a seven-contract resolver family, six unpublished C2 hosts, a campaign timeline reaching back to May 2025, and a family-wide event-topic anchor that defeats IP rotation."
tlp: CLEAR
---

> **TL;DR** — In early 2026, several vendors documented the Iranian-nexus actor **MuddyWater** (MOIS; aka Seedworm, Static Kitten, Mango Sandstorm, TA450) using **EtherHiding** — storing command-and-control configuration inside an Ethereum smart contract — to drive the **Tsundere** botnet. Each report described a *single* contract. Working the problem from the blockchain side, I found that contract is one member of a **seven-contract resolver family**, resolving to **eight C2 hosts (six previously unpublished)**, deployed in waves beginning **May 2025** — roughly seven months before the first public disclosure. The most valuable artifact isn't any IP: it's a **shared `StringChanged` event topic** that enumerates the entire family and survives the operator's per-host rotation. The same immutability that makes EtherHiding takedown-resistant also makes the operator's update history permanently auditable. This post walks through the mechanics, the methodology, the infrastructure, and the detection content — and stays carefully calibrated about what's novel versus what's adoption of a Russian-origin malware-as-a-service.
>
> Repository, IOCs, and detections: [`github.com/yankywilson/muddywater-etherhiding-resolver-family`](https://github.com/yankywilson/muddywater-etherhiding-resolver-family) · **TLP:CLEAR**

---

## Table of contents

1. [Why this matters](#1--why-this-matters)
2. [Primer: how EtherHiding actually works](#2--primer-how-etherhiding-actually-works)
3. [The starting point: one contract, in isolation](#3--the-starting-point-one-contract-in-isolation)
4. [The pivot: the operator signs their own update history](#4--the-pivot-the-operator-signs-their-own-update-history)
5. [Enumerating the family (reproducible methodology)](#5--enumerating-the-family-reproducible-methodology)
6. [Inside the resolver contract](#6--inside-the-resolver-contract)
7. [Inside the Tsundere bot](#7--inside-the-tsundere-bot)
8. [Mapping the infrastructure](#8--mapping-the-infrastructure)
9. [Reconstructing the timeline](#9--reconstructing-the-timeline)
10. [Corroboration, calibration, and what's actually novel](#10--corroboration-calibration-and-whats-actually-novel)
11. [Attribution: adoption, not invention](#11--attribution-adoption-not-invention)
12. [Detection engineering](#12--detection-engineering)
13. [Defensive recommendations](#13--defensive-recommendations)
14. [Honest limitations and validation status](#14--honest-limitations-and-validation-status)
15. [Indicators of compromise](#15--indicators-of-compromise)
16. [Investigation timeline](#16--investigation-timeline)
17. [Closing thoughts](#17--closing-thoughts)

---

## 1 · Why this matters

Defenders have spent two decades building muscle memory around a simple loop: find the adversary's infrastructure, block it, and burn it. Domains get sinkholed. IPs get null-routed. Hosting providers get abuse complaints. The entire indicator-of-compromise economy assumes there is *somewhere to point the takedown*.

EtherHiding breaks that assumption. When command-and-control configuration lives inside an immutable smart contract on a public blockchain, there is no domain to seize, no server to subpoena, and no registrar to serve. The malware reads its next instruction with a **free, read-only call that leaves no trace on the ledger**. For a state actor operating under the degraded command conditions Iran has faced since the February 2026 regional escalation, this is close to ideal: infrastructure that keeps functioning without any live operator coordination at all.

So when MuddyWater — a group historically associated with PowerShell, RMM abuse, and fairly conventional C2 — turned up using EtherHiding, it was worth a hard look. The public reporting answered *what* (the technique) and *which sample* (one contract, one node). It did not answer the questions a defender actually needs answered:

- Is this one contract, or a system?
- How long has it been running?
- What can I detect that **won't expire the moment the operator rotates an IP**?

This investigation set out to answer those three questions. The answers turned out to be: a system, longer than anyone reported, and — happily — quite a lot.

---

## 2 · Primer: how EtherHiding actually works

If you already live in smart-contract internals, skip ahead. If you're a malware analyst who has mostly avoided the blockchain, this section is the mental model you need for the rest of the post.

A smart contract is just code and persistent storage living at an address on a blockchain. Anyone can interact with it in two fundamentally different ways:

| Interaction | Costs gas? | Creates a transaction? | Leaves a permanent record? | Who can see it? |
|---|---|---|---|---|
| **Read** (`eth_call`) | No | **No** | **No** | Nobody — it's a local query against a node |
| **Write** (a transaction) | Yes | **Yes** | **Yes, forever** | Everyone — it's in the public ledger |

EtherHiding exploits the asymmetry in that table.

**The malware only ever reads.** When a Tsundere implant wants its current C2 address, it issues an `eth_call` to a resolver contract — effectively asking the contract, "what string are you storing right now?" Because `eth_call` is a read, it:

- costs nothing (no wallet, no gas, no funding trail),
- produces no on-chain transaction,
- is indistinguishable, at the node level, from any other blockchain query, and
- can be sent to **any** public RPC endpoint, so blocking one provider accomplishes nothing.

That's the resilient half. Here's the half the operator can't avoid.

**The operator must write.** To change the C2 — to rotate to a new host — the operator has to call a setter function on the contract, and *that* is a transaction. It costs gas, it's signed by their wallet, and it is recorded on the public ledger permanently. Worse for them, the contract **emits an event** every time the value changes, and that event is indexed by a deterministic **topic hash**.

This is the seam. The very immutability that protects the adversary's reads makes their writes a permanent, queryable confession. The rest of this investigation is built on pulling that thread.

---

## 3 · The starting point: one contract, in isolation

The public reporting that opened this case was solid work. Between **March 4 and March 12, 2026**, Ctrl-Alt-Intel, Hunt.io, Check Point, and eSentire's Threat Response Unit independently tied MuddyWater to the Tsundere botnet and to EtherHiding. eSentire's analysis disclosed the concrete artifact: a resolver contract at

```
0x2B77671cfEE4907776a95abbb9681eee598c102E
```

and a C2 node at `185.236.25.119` on **AS400992 (ZhouyiSat Communications)**. Hunt.io, working the host side, traced a multi-stage PowerShell dropper (`reset.ps1`) with an explicit `ethers.js` dependency to the same node, and JUMPSEC later documented the Node.js implant — "ChainShell" — that resolves its C2 from an Ethereum contract.

Five independent sources, converging on one technique. Excellent corroboration. But every one of them treated the contract as a **single artifact** — a curiosity to be screenshotted and added to an IOC table. None asked whether it was the only one.

That gap is understandable. From the host or sample side, you see the one contract the sample you have points at. To see the rest, you have to stop looking at samples and start looking at the chain.

---

## 4 · The pivot: the operator signs their own update history

The disclosed contract is, under the hood, disguised as an ERC-20 token but built around two functions that betray its real purpose:

```
getString(address)   →  selector 0x7d434425    // the bot's read path (eth_call)
setString(string)    →  selector 0x7fcaf666    // the operator's write path (transaction)
```

When the operator calls `setString` to push a new C2, the contract emits an event. On Ethereum, every event is identified by **`topic0`** — the Keccak-256 hash of the event's signature. For this resolver family, that hash is:

```
0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47
```

Here is the insight the whole investigation turns on:

> **That topic is not unique to one contract. It is identical across every contract the operator deployed from the same source.**

The operator reused their resolver code. Every contract they minted emits the *same* `StringChanged` topic. Which means you don't have to know the contracts in advance — you can ask the entire Ethereum ledger a single question:

> *"Show me every log, from every contract that has ever existed, whose `topic0` equals `0x3ca6280d…2d47`."*

The answer to that question **is the campaign**. It returns every resolver contract in the family, and — because the changed C2 string is in each event's data field — every C2 host any of them has ever pointed to, retroactively and prospectively, regardless of how many times the operator rotates IPs afterward.

The adversary built infrastructure specifically to be un-blockable. In doing so, they made it permanently **enumerable**.

---

## 5 · Enumerating the family (reproducible methodology)

Everything below was performed **passively against public ledger data and public RPC endpoints**. No adversary infrastructure was contacted directly; reading a public blockchain is not touching the C2. This is air-gapped, read-only OSINT in the most literal sense.

### 5.1 The one-line version (block explorer)

The fastest path needs no tooling. On Etherscan, open the disclosed contract, switch to the **Events** tab, and you'll see `StringChanged` emissions with decoded data containing the C2 strings. To pivot from one contract to the family, you query the topic directly rather than the address.

### 5.2 The reproducible version (`web3.py`)

```python
from web3 import Web3

# Any public RPC works; rotate providers to avoid rate limits.
w3 = Web3(Web3.HTTPProvider("https://eth.llamarpc.com"))

STRINGCHANGED_TOPIC = (
    "0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47"
)

# Sweep the chain for every contract that emits this topic.
logs = w3.eth.get_logs({
    "fromBlock": 0,
    "toBlock": "latest",
    "topics": [STRINGCHANGED_TOPIC],
})

family = {}
for log in logs:
    contract = log["address"]
    # The changed C2 string lives in the event data; decode as UTF-8.
    raw = bytes.fromhex(log["data"][2:])
    c2 = raw.split(b"\x00")[0].decode("utf-8", "ignore").strip()
    family.setdefault(contract, []).append(c2)

for contract, c2s in family.items():
    print(contract, "->", sorted(set(c2s)))
```

In practice you'll chunk `fromBlock`/`toBlock` into windows (most public RPCs cap log ranges), and you'll deploy the same query against several of the bot's own RPC providers to cross-check completeness. The output is the contract-to-C2 map reproduced in the [IOC section](#15--indicators-of-compromise).

### 5.3 The CLI version (`cast`, from Foundry)

```bash
# Pull the raw input data of an operator's setString transaction...
cast tx <txhash> --rpc-url https://eth.merkle.io | grep input

# ...and decode the embedded C2 string.
cast --to-ascii 0x<input_hex>
```

### 5.4 Reading a single resolver without touching the operator

To confirm what a given contract is serving *right now*, you call its getter — a read, not a write:

```bash
cast call <contract> "getString(address)(string)" <query_arg> \
     --rpc-url https://ethereum-rpc.publicnode.com
```

The `<query_arg>` is the address the bot passes; for the disclosed contract it is `0x002E9Eb388CBd72bad2e1409306af719D0DB15e4` (recovered from the bot, see §7).

The result of running this methodology: **seven distinct resolver contracts**, bound by the shared topic, resolving to **eight C2 hosts** across three deployment waves.

---

## 6 · Inside the resolver contract

The resolver is deliberately unremarkable on the surface. It presents as a standard ERC-20 token — name, symbol, the usual transfer scaffolding — so that a casual glance at the address on a block explorer sees "just another token contract." The malicious capability is two extra functions bolted onto that disguise:

- **`getString(address) → string`** (`0x7d434425`): the read path. The bot calls this via `eth_call`. The `address` argument acts as a lightweight key/namespace — a way for the operator to serve different values to different lookups from the same contract if they choose.
- **`setString(string)`** (`0x7fcaf666`): the write path. Only the operator calls this, and only as a gas-paying transaction, which is what emits the tell-tale `StringChanged` event.

Compilation metadata puts the contracts at **Solidity `v0.8.30`**. The reuse of identical bytecode across the family is what produces the identical event topic — and it's also a minor operational-security failure on the adversary's part: had they varied the event signature per contract, the family-wide pivot in §4 would not exist.

The **per-host deployment pattern** is the other diagnostic detail. Rather than rotating the stored value inside a single long-lived contract, the operator deploys a **fresh contract for each new host**. That's why the originally-disclosed contract has remained unchanged since December 2025 even after it was publicly burned — burning one contract doesn't compromise the others, and the family scales horizontally. It's a sensible design for resilience. It's also why enumerating the family matters so much: each contract is a separate node in the campaign graph that the single-contract reporting never saw.

---

## 7 · Inside the Tsundere bot

Static analysis of the Tsundere Node.js bot — performed in an isolated environment, never executed against live infrastructure — confirmed the on-chain findings from the malware side and filled in the implant's capabilities.

**The dead-drop lookup.** The bot is hardcoded with the resolver contract `0x2B77671cfEE4907776a95abbb9681eee598c102E` and the query argument `0x002E9Eb388CBd72bad2e1409306af719D0DB15e4`. It resolves its C2 by calling `getString` via `eth_call`.

**RPC redundancy as a design choice.** Rather than trusting a single blockchain gateway, the bot rotates across **ten public Ethereum RPC endpoints**:

```
eth.llamarpc.com            mainnet.gateway.tenderly.co
rpc.flashbots.net           rpc.mevblocker.io
eth-mainnet.public.blastapi.io   ethereum-rpc.publicnode.com
eth.drpc.org                eth.merkle.io
(+2 additional providers)
```

This matters for two reasons. First, it tells you this is a *mature* implant, not a proof of concept — the author anticipated that defenders might block individual RPC providers and built in failover. Second, it gives defenders a concrete, if subtle, network signature (see §12): a server-side Node.js process reaching out to multiple public Ethereum RPC endpoints is doing something unusual.

**Capabilities, post-resolution.** Once the bot has its C2, it:

- connects over a **cleartext WebSocket to `ws://<ip>:3001`**,
- encrypts C2 traffic with **AES-CBC**,
- fingerprints the host with **`execSync`** (shelling out to gather system context), and
- executes operator-supplied code via **`new Function()`** — arbitrary JavaScript RCE.

That last primitive is worth pausing on. `new Function()` turns the bot into a generic execution engine: the operator can push arbitrary logic at runtime without ever shipping a new binary. Combined with blockchain C2 resolution, the implant is both hard to find *and* hard to pin to a fixed capability set.

---

## 8 · Mapping the infrastructure

Resolving the family's `StringChanged` events produced the C2 strings; OSINT pivots (Censys, Shodan, passive DNS, certificate analysis) characterized the hosts behind them. The result is a far richer infrastructure picture than the single disclosed node.

**Two hosts are live** as of publication:

- **`185.236.25.119`** — AS400992 (ZhouyiSat / JaJoJoo). The publicly-disclosed node. Runs both an exposed operator **panel** and a C2 listener.
- **`45.153.34.146`** — AS51396 (**PFCLOUD / VMHeaven.io**, NL). A C2-**listener-only** node with **no panel exposed** — and, notably, on a bulletproof provider that does **not** appear in any prior public MuddyWater reporting. This is new infrastructure, not a re-report.

**A burned host was recycled, not discarded.** `85.90.197.26` (AS8254, GREEN FLOID, GR) — a former C2 from the August 2025 wave — now runs an **FRP (Fast Reverse Proxy) relay** (`frps 0.65.0` on tcp/8080), with this TLS fingerprint:

```
cert SHA-256 : f538155177d9321665a29920933f124ac9edda4e54e6c5002546f917c44848eb
cert SPKI    : 8806818a8f09f0352e29b7152afb2ab3b1e1fc57ca318cefe12e483a3a893d27
```

The repurposing is a small but revealing detail: this is an operator who **costs out their infrastructure** and re-tasks burned nodes into relay duty rather than abandoning them. Nothing is wasted.

**The operator panel has a fingerprint.** Where a panel is exposed, it self-identifies:

```
HTTP title       : "Tsundere Netto"
server           : nginx/1.27.4
Next.js build id : G072H3a1MQpdtoq3Hnw9V
auth error JSON  : POST /api/auth/login → {"error":"User not found.","code":20003}
```

That `code: 20003` / `"User not found."` schema is distinctive enough to hunt for across internet-scan datasets — a way to discover *future* panels before their C2s are otherwise known.

The remaining hosts (`45.140.17.123`, `77.93.155.167`, `104.219.234.251`, `67.220.74.132`) span Scalaxy (NL), Database Mart (US), DataWagon (US), and GTHost (US) — a deliberate spread across small, cheap, weakly-monitored providers in multiple jurisdictions. The full mapping is in §15.

---

## 9 · Reconstructing the timeline

Because every resolver deployment is a transaction with a block timestamp, the family carries its own dating. The deployments cluster into **three waves**:

| Wave | When | What it tells us |
|---|---|---|
| **Wave 1** | **May 2025** | Earliest known deployment. The single contract everyone reported is *not* here — the campaign predates it. |
| **Wave 2** | **August 2025** | The bulk of the family, including the host later recycled into the FRP relay. |
| **Wave 3** | **December 2025** | The contract that public reporting would disclose three months later. |

The headline: MuddyWater's EtherHiding operations began **around May 2025 — roughly seven months before the first public disclosure in March 2026.** This reframes the technique from "a 2026 novelty MuddyWater just picked up" to "a capability quietly pre-positioned through 2025." Given the regional escalation that followed in early 2026, infrastructure that was already deployed and battle-tested before the crisis is exactly what you'd expect a competent service to have built ahead of need.

One honest caveat, carried from the formal assessment: deployment timestamps establish when a contract was *created*, not the precise moment it was first *weaponized* against a victim. The inference from a three-wave deployment cadence to operational use is strong, but it is an inference — hence the moderate-confidence rating on the seven-month figure.

---

## 10 · Corroboration, calibration, and what's actually novel

Good intelligence is as careful about what it *doesn't* claim as what it does. Here's the honest ledger.

**Corroborated (technique level).** MuddyWater + EtherHiding + Tsundere is confirmed by five independent vendors. None of the novelty claims here contradict that work; they extend it.

**Novel (this research).** The following are first published here and absent from all external reporting reviewed at time of writing:

- the **family-wide `StringChanged` event-topic anchor**,
- the **seven-contract family** and **six new C2 hosts**,
- the **bulletproof provider PFCLOUD/VMHeaven.io (AS51396)** in a MuddyWater context,
- the **FRP-relay recycling** of a burned C2, and
- the **May 2025 origin** and three-wave timeline.

**Corrected (calibration notes that didn't make the headline).** Three working assumptions broke under scrutiny and are documented as corrections rather than buried:

- An adjacent claim that the **Druidfly** wiper family had *no* 2025–2026 public samples is **false** — a Druidfly sample dated 2025-06-24 exists on MalwareBazaar. The defensible, scoped statement is that **no wiper of any family appears in the 103-sample MuddyWater corpus (2020–2026)**.
- **DinDoor** is frequently lumped in with wipers; it is a **Deno-runtime backdoor**, not a wiper.
- **"Operation Olalampo"** (Group-IB) is a *separate*, Telegram-bot-C2 MuddyWater campaign. It must **not** be conflated with the EtherHiding/Tsundere strand; they share only the actor.

Reporting the corrections with the same prominence as the discoveries is the entire point. A reader who sees that the negative and contradicting evidence is handled honestly has reason to trust the positive claims.

---

## 11 · Attribution: adoption, not invention

It would be easy — and wrong — to headline this as "MuddyWater pioneers blockchain C2." The accurate framing is narrower and more interesting.

EtherHiding has a lineage. It first appeared in **September 2023** in the financially-motivated **CLEARFAKE / UNC5142** campaign. It crossed into nation-state use in **October 2025**, when Google's Threat Intelligence Group documented **North Korea's UNC5342** as the first state adopter. MuddyWater's use in early 2026 is therefore the **first *Iranian*-nexus adoption** — a genuine first, but a first in *adoption*, not in *invention*.

The Tsundere botnet itself bears strong marks of **Russian-speaking criminal authorship**: eSentire documented CIS-geofencing logic that terminates execution on hosts located in Commonwealth of Independent States countries — a classic self-protection measure by developers wary of their own domestic law enforcement. This points squarely at a **Russian-origin malware-as-a-service**, consumed by an Iranian state operator, not built by one.

So the calibrated claim — the one I'm willing to defend to other analysts — is precisely this:

> *An Iranian state actor adopted blockchain-based C2 by purchasing into a Russian criminal malware-as-a-service ecosystem. The novel contribution of this research is the detailed mapping of the **infrastructure** behind that adoption: the contract family, the timeline, the live hosts, and the durable on-chain anchor.*

That distinction is not pedantry. Conflating "first Iranian use" with "Iranian-developed" would mislocate the capability's origin and corrupt downstream attribution for anyone who builds on this work. The convergence of state actors onto criminal MaaS is itself one of the most important trends in this space — and getting the direction of the supply chain right is part of reporting it accurately.

---

## 12 · Detection engineering

This is the part that turns research into defense. The detections fall into three planes, ordered by durability.

### 12.1 The on-chain plane (most durable)

The `StringChanged` topic is the highest-value indicator in this entire investigation because it is immune to IP rotation. Two uses:

**Enumerate (threat-intel side).** Run the §5 query on a schedule. Any *new* resolver contract emitting the family topic is a new C2 host appearing in real time — you detect the operator's next move as they make it.

**Hunt (network side).** Alert on internal hosts reaching out to **public Ethereum RPC endpoints** where no legitimate blockchain workload exists — especially from **server-side processes**. A KQL sketch for an environment with proxy/DNS telemetry:

```kql
let ethRpcEndpoints = dynamic([
  "eth.llamarpc.com","mainnet.gateway.tenderly.co","rpc.flashbots.net",
  "rpc.mevblocker.io","eth-mainnet.public.blastapi.io",
  "ethereum-rpc.publicnode.com","eth.drpc.org","eth.merkle.io"
]);
DeviceNetworkEvents
| where RemoteUrl has_any (ethRpcEndpoints)
| where InitiatingProcessFileName in~ ("node.exe","powershell.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP
```

Neither signal is malicious in isolation — plenty of legitimate software talks to Ethereum. The **combination** (server-side runtime + public RPC + an outbound `ws://…:3001` shortly after) is high-signal.

### 12.2 The network plane

```
# Suricata-style logic (illustrative)
alert tcp $HOME_NET any -> $EXTERNAL_NET 3001 (
    msg:"MuddyWater Tsundere — cleartext WebSocket C2 on tcp/3001";
    flow:established,to_server;
    content:"GET"; content:"Upgrade|3a 20|websocket"; nocase;
    classtype:trojan-activity; sid:1000001; rev:1;
)
```

Pair this with the **panel-discovery fingerprint** from §8 — hunt internet-scan data (Censys/Shodan) for the `"Tsundere Netto"` HTTP title, the `nginx/1.27.4` + Next.js build combination, and the `{"error":"User not found.","code":20003}` auth schema to surface panels (and therefore C2s) you don't yet have indicators for.

### 12.3 The host plane

YARA over the Node.js implant should key on the **co-occurrence** of the dead-drop primitives rather than any single string: the hardcoded contract address, the `getString`/`eth_call` resolution pattern, the RPC endpoint list, and the `new Function()` + `execSync` capability pair. The full rule set (10 Sigma, 10 Suricata, 4 YARA) ships in the [repository](https://github.com/yankywilson/muddywater-etherhiding-resolver-family).

---

## 13 · Defensive recommendations

1. **Treat public-blockchain RPC traffic as a monitorable egress class.** Most enterprises have zero legitimate need for server-side hosts to query Ethereum. Baseline it; alert on deviations.
2. **Operationalize the on-chain anchor, not just the IPs.** Block the live hosts, yes — but build the §5 enumeration into your intel pipeline so new family members are caught automatically. The IPs will rotate; the topic won't.
3. **Hunt for the panel fingerprint proactively.** The `"Tsundere Netto"` / `code:20003` signature lets you find infrastructure *before* it's used against you.
4. **Don't over-trust takedowns here.** You cannot seize a smart contract. Defense against EtherHiding is detection-and-response, not disruption — plan accordingly.
5. **Watch the supply chain, not just the actor.** Because the capability came from a Russian MaaS, the leading indicator that *other* Iranian clusters adopt blockchain C2 is renewed contact with that same criminal ecosystem. APT34 and APT35 are the clusters to watch.

---

## 14 · Honest limitations and validation status

In the spirit of the calibration this whole post argues for, here is what is *not* yet nailed down:

- **The six new C2 hosts are confirmed novel pending one check:** that they are not embedded inside the three public Tsundere/ChainShell samples now on MalwareBazaar (two JS samples dated 2026-05-10; one PowerShell dated 2026-03-04). The **event-topic anchor and the family-enumeration method are unaffected either way**, because they derive from the operator's on-chain behavior rather than from any single sample. If a host turns up inside a public sample, it simply moves from "new" to "previously disclosed."
- **Sibling contract addresses are held at partial precision** in the public IOC set; the full addresses are recoverable by anyone running the §5 enumeration, which is intentional — the method is the durable deliverable.
- **The May-2025 origin is moderate-confidence**, bounded by the contract-creation-versus-weaponization gap discussed in §9.
- **All findings are bounded by open-source visibility.** Closed commercial platforms were not queried; absence of corroboration there is unknown, not disproven.

None of these caveats are fatal. All of them are stated so that a peer reviewing this work knows exactly where the load-bearing claims sit.

---

## 15 · Indicators of compromise

**TLP:CLEAR — released for community detection use.** Machine-readable versions (CSV / ThreatFox-ready) are in the [repository](https://github.com/yankywilson/muddywater-etherhiding-resolver-family).

### On-chain

| Indicator | Value |
|---|---|
| Family event topic (`StringChanged`) | `0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47` |
| `getString(address)` selector | `0x7d434425` |
| `setString(string)` selector | `0x7fcaf666` |
| Disclosed contract | `0x2B77671cfEE4907776a95abbb9681eee598c102E` |
| Bot query argument | `0x002E9Eb388CBd72bad2e1409306af719D0DB15e4` |
| Compiler | Solidity `v0.8.30` (disguised as ERC-20) |

### C2 and infrastructure hosts

| IP | Role | ASN / provider | Status |
|---|---|---|---|
| `185.236.25.119` | C2 + operator panel (live) | AS400992 ZhouyiSat / JaJoJoo | Disclosed |
| `45.153.34.146` | C2 listener, no panel (live) | AS51396 PFCLOUD / VMHeaven.io (NL) | **New** |
| `85.90.197.26` | FRP relay (ex-C2) | AS8254 GREEN FLOID (GR) | **New** |
| `45.140.17.123` | C2 (dormant) | AS58061 Scalaxy (NL) | **New** |
| `77.93.155.167` | C2 (dormant) | AS401479 Database Mart (US) | **New** |
| `104.219.234.251` | C2 (recycled — validate) | AS27176 DataWagon (US) | **New** |
| `67.220.74.132` | C2 (recycled — validate) | AS63023 GTHost (US) | **New** |

### Network / fingerprints

| Indicator | Value |
|---|---|
| Tsundere C2 transport | cleartext WebSocket, `ws://<ip>:3001` |
| FRP relay | `frps 0.65.0`, tcp/8080 |
| FRP cert SHA-256 | `f538155177d9321665a29920933f124ac9edda4e54e6c5002546f917c44848eb` |
| Operator panel | HTTP title `"Tsundere Netto"`; `nginx/1.27.4`; Next.js build `G072H3a1MQpdtoq3Hnw9V` |
| Panel auth schema | `POST /api/auth/login → {"error":"User not found.","code":20003}` |
| Bot capabilities | AES-CBC C2 · `execSync` fingerprinting · `new Function()` RCE |

---

## 16 · Investigation timeline

| Date | Event |
|---|---|
| **May 2025** | First resolver contracts deployed (Wave 1) — campaign origin |
| **Aug 2025** | Bulk of the family deployed (Wave 2), incl. the future FRP-relay host |
| **Dec 2025** | The later-disclosed contract deployed (Wave 3) |
| **Mar 4–12, 2026** | Public disclosures (Ctrl-Alt-Intel, Hunt.io, Check Point, eSentire TRU); JUMPSEC follows |
| **Apr–Jun 2026** | This investigation: on-chain enumeration, bot deobfuscation, infrastructure mapping |
| **Jun 11, 2026** | Publication — TLP:CLEAR |

---

## 17 · Closing thoughts

There's a lesson in here that outlasts this particular campaign.

Adversaries adopt techniques like EtherHiding to escape the parts of our playbook that depend on *someone to point at* — a domain, a server, a provider. And for the disruption half of defense, it works: you genuinely cannot take down a smart contract.

But resilience and stealth are not the same property, and adversaries routinely conflate them. The blockchain that makes MuddyWater's reads untraceable makes their writes permanent. The code reuse that made their family cheap to deploy made it trivial to enumerate. The bulletproof design, pursued to its logical end, produced a single immutable topic hash that unrolls the entire operation.

The takedown era is ending for this class of infrastructure. The detection era is wide open. The trick is to stop asking "where do I point the takedown?" and start asking "what did the adversary have to make permanent in order to function?" For EtherHiding, the answer was their own update history — and once you have that, the bulletproof becomes the easiest thing in the world to watch.

---

*Independent research, published TLP:CLEAR for community defensive use. Full IOCs, detection rules (Sigma / Suricata / YARA / KQL), and the formal ICD-203 assessment are in the [companion repository](https://github.com/yankywilson/muddywater-etherhiding-resolver-family). Confidence levels and source ratings follow ICD-203 and are the author's own. Corrections and collaboration welcome.*

*— Yanky Wilson · [github.com/yankywilson](https://github.com/yankywilson) · [csoonline.com/profile/yanky-wilson](https://www.csoonline.com/profile/yanky-wilson)*
