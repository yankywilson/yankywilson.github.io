---
layout: post
title: "One kit, many flags: the distributed EtherHiding builder that North Korea and Iran are both renting"
date: 2026-06-15 12:00:00 -0400
categories: [threat-intelligence]
tags: [etherhiding, etherrat, tsundere, muddywater, dprk, blockchain-c2, maas, on-chain, ioc, detection-engineering]
excerpt: >-
  DPRK and Iranian operators are independently renting the same most-likely-Russian EtherHiding C2 kit. Shared supplier, independent customers.
---
> **TL;DR.** Public reporting describes EtherHiding C2 as a contract here, a contract there. It is not. On-chain, it is a single **builder kit** — 24 byte-identical and 9 variant resolver contracts on Ethereum mainnet, written to by roughly 30 operator wallets, fronting 52 live panels. Two of those operators are state-aligned: **North Korea** (the EtherRAT backdoor) and **Iran** (MuddyWater, deploying the Tsundere botnet). Both run the same resolver kit, bound by the same on-chain event-topic anchor and the same bytecode. The kit's lineage most likely traces to the **Russian-speaking criminal MaaS ecosystem**. This is not a North Korea–Iran partnership. It is two government programs shopping at the same criminal store — and the blockchain they chose for resilience has quietly become a permanent ledger of who shopped, when, and for what. Detection pack and full assessment: [`etherhiding-etherrat-kit`](https://github.com/yankywilson/etherhiding-etherrat-kit) and [`etherrat-onchain-c2-detection`](https://github.com/yankywilson/etherrat-onchain-c2-detection).

I want to walk through something the public reporting has documented in pieces but has not connected. Each vendor that has touched EtherHiding — Sysdig on EtherRAT, eSentire on the retail intrusion, Kaspersky on Tsundere — has described a single smart contract or a single malware family. What you don't see in any one report is the shape of the thing all of them are standing on: one shared resolver kit, used in parallel by a North Korean implant, an Iranian APT, and a couple dozen unattributed crimeware operators, all reading their C2 out of the same family of contracts.

This post is the synthesis of three of my own investigations — the distributed EtherRAT kit, the DPRK/Iran shared-builder link, and the MuddyWater/Tsundere on-chain family. It is more technical, and more willing to commit to an intelligence judgment, than any single repository, because the judgment only becomes defensible once you put the three together. Everything below is reproducible from public sources. Where a link was observed I say so; where it is inferred I say that too.

## EtherHiding in two minutes

EtherHiding is a dead-drop resolver (ATT&CK **T1102.001**) built on a public blockchain. The malware does not hardcode its C2 address. Instead it reads the address out of a smart contract on Ethereum mainnet at runtime, by issuing an `eth_call` to a public RPC provider. That read is free, generates no on-chain transaction, and — critically — leaves no DNS trail, because the C2 address never passes through name resolution.

The contract itself is trivially simple. Decompiled, it is a single string store:

| Element | Value |
|---|---|
| Storage model | `mapping(address => string)` keyed on `msg.sender` |
| Write | `setString(string)` — selector `0x7fcaf666` |
| Read | `getString(address)` — selector `0x7d434425` |
| Event on write | `StringChanged(address account, string newString)` |
| Event topic-0 | `0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47` |
| Compiler | Solidity 0.8.30 |

To rotate C2, an operator sends one `setString` transaction. The new endpoint is written to storage under their own wallet address and the contract emits `StringChanged`. The implant, on its next beacon, queries several public RPC providers in parallel — `blastapi.io`, `drpc.org`, `merkle.io`, `publicnode.com`, `tenderly.co`, `mevblocker.io`, `flashbots.net` — and takes the majority answer, which makes the resolution robust against any single provider blocking or returning stale data.

There is no takedown. You cannot serve a registrar a notice on a smart contract; you cannot null-route the Ethereum mainnet. An operator who loses every server can reassert control over months-old infections with a single cheap transaction.

That is the design goal. The design **cost** — which is the whole intelligence opportunity here — is that every one of those `setString` writes is permanent, public, timestamped, and attributable to a wallet. The operators built themselves a takedown-proof C2 layer and, in the same move, a takedown-proof confession.

## The kit, not the contract

Here is the reframing that the per-vendor reporting misses. The two selectors above, the storage model, and that `StringChanged` topic are not unique to one contract. They are the fingerprint of a **builder kit**.

Pulling the runtime bytecode of the publicly named contracts and pivoting on the shared topic and the shared Solidity compiler-metadata IPFS hash (`1de57633…`), the family resolves to **24 byte-for-byte-identical contracts plus 9 minor variants** on Ethereum mainnet — against the single contract most public write-ups describe. Across those contracts, roughly **30 distinct operator wallets** have written C2 endpoints, and decoding the `StringChanged` events directly off-chain recovers **19+ cleartext C2 endpoints**, several never previously published.

The storage model is the tell. Because state is keyed on `msg.sender`, a single contract instance can serve many operators at once — each operator's C2 is namespaced under their own wallet. And because the kit ships the contract source for operators to deploy themselves, you get many byte-identical instances. That is a **per-operator fan-out** architecture. It is the on-chain signature of malware-as-a-service, not of a single intrusion set.

Fronting the C2 tier is a server-side panel with a stable HTTP fingerprint — a CORS response advertising a custom `X-Bot-Server` header. A header search across internet-scan data enumerated **52 live panels**, clustering on NEKO / NEKOBYTE INTERNATIONAL LTD (AS206134, Frankfurt), with additional hosts on Microsoft Azure and UK residential ranges. (A caveat I put in the repo and will repeat here: the panel's `ETag` is the default Express 404 body hash and appears on thousands of unrelated hosts — use the `X-Bot-Server` header, or the header intersected with the ASN, never the ETag alone.)

One live resolver instance, `0x45729d7424d7310a0c041a2906ba95a4bd5ebfca`, written by operator wallet `0xA001D3863b138eD523f255f62725AB1ddc82af87`, holds C2 endpoints including `isocell.swedencentral.cloudapp.azure.com`, `dmors.com` and `leopriego.com` in cleartext. The public ThreatFox dataset independently tags several other on-chain-recovered endpoints — `rubysen.com`, `ager-stp.org`, `issueall.com`, `webiqonline.com`, `dakindsoups.com` — as EtherRAT, reported by an unrelated researcher. Three independent methods — on-chain decode, host fingerprinting, community attribution — converging on the same family is what carries the kit assessment at **high confidence**.

## The anchor that ties the flags together

Now the part that matters for the headline. That `StringChanged` topic — `0x3ca6280d…` — is not just the EtherRAT family anchor. It is **also** the anchor on a second, separately documented contract family: the seven-contract resolver set behind **MuddyWater's Tsundere botnet** ([`muddywater-etherhiding-resolver-family`](https://github.com/yankywilson/muddywater-etherhiding-resolver-family)).

The two clusters — the North Korean EtherRAT contracts and the Iranian Tsundere contracts — emit the **identical event topic**, and the identical-bytecode set shares the **identical compiler-metadata IPFS hash**. That is not "similar code." An IPFS metadata-hash match means the same source file, compiled with the same compiler version and the same settings, produced both. This corroborates *on-chain* what eSentire reported only as source-code overlap between EtherRAT and Tsundere ([eSentire TRU](https://www.esentire.com/blog/etherrat-sys-info-module-c2-on-ethereum-etherhiding-target-selection-cdn-like-beacons)). I assess the shared builder/codebase across the DPRK and Iranian clusters at **high confidence**.

I'll state the boundary just as plainly: a shared builder is a **tooling** link, not an operational one. It tells you both operators bought from the same shelf. It tells you nothing, by itself, about whether they ever talked to each other.

## Three consumers, three flags

The on-chain kit is one thing; the actors riding it are attributed externally, by the malware families they run.

**North Korea — EtherRAT.** Sysdig first linked EtherRAT to DPRK on the strength of tooling overlap with the "Contagious Interview" campaign; that attribution has since been echoed by eSentire and Atos. EtherRAT is a Node.js backdoor that runs arbitrary commands, fingerprints the host, and steals wallets and cloud credentials. Delivery in the campaigns I corroborated runs through SEO-optimized GitHub "facade" repositories impersonating IT utilities — PsExec, AzCopy, Sysmon, LAPS — and a malicious MSI. I detonated one such loader, `v9.msi` (SHA-256 `56058b92…`, 0/61 AV), and watched the chain in sandbox:

```
v9.msi  (msiexec /qb)
  └─ drops node.exe  (masqueraded under \Program Files (x86)\Common Files\Oracle\Java\javapath\)
  └─ drops JS stage  cDQMlQAru0.xml  (Node script, .xml-disguised; SHA-256 bbc4150d…)
  └─ conhost --headless "node.exe" "...\2PhU26hCp7GZ\cDQMlQAru0.xml"
        └─ JS stage queries public Ethereum RPC providers  →  resolves C2
        └─ beacons to kit panel  31.76.16.211
  └─ persistence: Run-key autostart (reg.exe)
  └─ anti-analysis: PowerShell VM/sandbox checks, USB-bus check, AV enumeration
```

That confirms the EtherHiding mechanism on a live sample: the loader does resolve C2 through Ethereum RPC and does reach a kit panel. (The honest limit is narrow and purely technical: the RPC calls are TLS-encrypted, so the trace proves *which mechanism* and *which panel*, but not *which contract address* the script read — that lives inside the JS stage. I carry that one link as a tight inference, not an observation.) The DPRK attribution, by contrast, is **high confidence**, and it does not rest on any single vendor. Sysdig made the original call on Contagious Interview tooling overlap; eSentire confirmed it through its own live incident response; Atos confirmed it through independent monitoring, tying it to Lazarus. More to the point, the *tradecraft* is DPRK-diagnostic on its own — fake-recruiter and IT-support social engineering, SEO-optimized GitHub facade repos, and theft objectives centered on cryptocurrency wallets and cloud credentials are the financial-motivation signature North Korea has run for years. Malware label, delivery tradecraft, and victimology all converge on the same flag. That convergence, not one report, is what carries it.

**The supplier — Tsundere, a Russian-speaking MaaS.** Tsundere is a separate Node.js botnet that Kaspersky's GReAT attributes to a Russian-speaking operator using the handle "koneko," with CIS-geofencing and CIS-language checks consistent with a product sold inside a Russian-speaking criminal market. Its C2 listener is a cleartext WebSocket on port `3001`; its panel renders a "Tsundere Netto" title on nginx/1.27.4, served by a Next.js build I fingerprinted as `G072H3a1MQpdtoq3Hnw9V`, and it returns a distinctive auth error — `{"error":"User not found.","code":20003}` — that doubles as a host-hunting selector. I assess the Russian-speaking-MaaS lineage at **moderate–high**. This is the thread that makes "Russian criminal infrastructure" the most likely origin of the shared kit — not the hosting (Russian VPS is procurement, not nationality), but the malware lineage.

**Iran — MuddyWater, deploying Tsundere.** eSentire found Tsundere staged on an open-directory server they attribute to MuddyWater (Iran; MOIS — note some vendors label this cluster APT34, which is a labeling quirk worth not over-reading). My on-chain work on the Iranian side recovered a **seven-contract resolver family** resolving to eight C2 hosts across May/August/December 2025 waves — six of them previously unpublished, and roughly seven months ahead of public disclosure. Highlights from that cluster:

- Live nodes on **AS400992 ZhouyiSat** (`185.236.25.119`, the exposed panel) and the previously-unreported bulletproof provider **PFCLOUD/VMHeaven.io, AS51396** (`45.153.34.146`, a listener-only node). The publicly disclosed Iranian contract `0x2B77671cfEE4907776a95abbb9681eee598c102E` resolves through operator address `0x002E9Eb388CBd72bad2e1409306af719D0DB15e4` to that ZhouyiSat panel — the published anchor my six unpublished hosts hang off.
- A tradecraft pivot where `85.90.197.26` was **repurposed from an August 2025 C2 into an FRP relay** (`frps 0.65.0`).
- An operator **fat-finger preserved forever on-chain**: a mistyped C2 IP, corrected by a second `setString` 24 seconds later. Both writes are permanent. You can watch the operator notice their own typo.
- **Strict per-host artifact hygiene.** This operator reuses nothing across hosts — no shared build IDs, no shared TLS certificates, no shared contracts at the host level. That discipline defeats the usual infrastructure-pivoting, and it is exactly *why* the on-chain resolver family and the cleartext `:3001` WebSocket are the only durable links left to pull. The blockchain is the seam the operator could not close.

## The bridge host

The clearest physical evidence that these are the same kit in the same hands-adjacent ecosystem is a single server. `91.215.85.42` (PROSPERO OOO, AS200593, St. Petersburg) was written into the EtherRAT family on-chain, and it confirmed live three independent ways: the on-chain write, a Shodan banner carrying the EtherRAT `X-Bot-Server` header on port `3000`, and a behavioral PCAP showing a detonated sample beaconing to it with **no preceding DNS lookup** (EtherHiding working as designed). What makes it the bridge: ports `3000` (EtherRAT) **and** `3001` (Tsundere's WebSocket C2) are open on the same host. The two implants' C2 listeners are co-resident — the infrastructure-level analogue of the code overlap. I assess `91.215.85.42` as a live C2 host at **high confidence**.

## The novel contract, and what the money says

Working the funding graph rather than the malware, I pivoted up from an EtherRAT operator wallet and found a **fourth resolver contract that appears in no vendor report** — `0x40A7d723F5Df6c88464bC95DBf7D96573fBc4f85` — bytecode-identical to the named ones, written once on 4 December 2025 with the domain `api-gateway-prod.com`. The funder wallet had both deployed that contract and seeded the operator 18 minutes later. Sample-driven discovery finds the contracts that show up in captured payloads; wallet-driven discovery finds the ones the operators deployed but barely used.

That novel domain also let me reconstruct a clean campaign lifecycle from certificate transparency alone. `api-gateway-prod.com` was issued exactly two Let's Encrypt certificates — a pre-cert and its leaf — both on **29 November 2025**, with no renewals and no subdomains ever, expiring **27 February 2026**. Lay that against the on-chain write of 4 December and you get the whole operational window without touching the host: **provisioned Nov 29 → weaponized Dec 4 → abandoned ~Feb 27**. The current IP it resolves to (`193.200.17.66`, BlueVPS) is a recycled MikroTik tenant and point-in-time noise; the durable indicators are the domain and the certificate hash `720db1ba…`. The generic SaaS name is camouflage — a name search returns ~1,250 legitimate results — so the cert hash, not the name, is the pivot.

Walking the DPRK funding chain to its end:

```
SideShift (no-KYC swap) → 0x564aa223 → 0x14afdDD6 → 0xE941A9b2 (EtherRAT operator)
                                          └── also deploys the novel contract 0x40A7d723…
```

The intermediaries are single-use, near-drained wallets. The chain terminates at SideShift, a no-KYC instant-swap exchange. And here is the negative that disciplines the whole thesis: the Iranian operators are funded by **entirely different** upstream wallets. There is **no shared funding wallet between the DPRK and Iranian clusters**. They share funding *typology* — no-KYC swaps — which is non-discriminating and common to half the threat landscape. They do not share funding *infrastructure*. That null result is exactly what "independent customers" predicts.

## Delivery and tradecraft

The on-chain layer is only the C2-resolution tier. Getting onto the box uses older, dirtier tricks, and the most interesting one in this kit is the **hijacked aged domain**.

The standout case is `aravisblog.com` — a legitimate 16-year-old WordPress/Automattic blog. Passive DNS shows it hosted on Automattic/Rackspace/AWS infrastructure continuously from 2010 through early 2026, then **repointed to a kit panel at `31.76.16.211`** (OOO Razvitie Optimizatsiya, RU) on **8 June 2026**. The point of stealing a domain that old is reputation laundering: at the time of analysis it carried just **1/91 vendor detections**. A clean 16-year history is a better shield than any new domain the operator could register, and most reputation systems will wave it straight through.

The takeover also published two non-standard DNS service-locator records — `_3389._https.aravisblog.com` and `_3300._https.aravisblog.com` — wiring up remote-access and panel services well beyond ordinary web hosting. That is a useful tell on its own: a decade-old blog suddenly advertising RDP-adjacent service records is not a blog anymore.

Alongside the hijacked domains, operators use throwaway domains and the SEO-optimized GitHub facade repositories described earlier (impersonating PsExec, AzCopy, Sysmon, LAPS). Network-side, the beacons are dressed as benign CDN traffic — requests for `.ico`, `.png` and `.css` paths with random hex and UUID components — and the JavaScript stages are packed with the free Obfuscator.io tool. None of that is exotic individually; the combination with a takedown-proof on-chain C2 tier is what makes the kit durable.

**Operational takeaway for defenders:** treat aged-domain reputation as necessary-not-sufficient. A 10-year-clean domain whose hosting ASN and service-record profile change within days is *itself* the anomaly — alert on the change, not the age.

## Reading the decoys

One more finding, because it is the one most likely to bite an analyst who ingests this kit's C2 in bulk. **Not every endpoint written to these contracts is live actor infrastructure.** The calldata contains decoys and recycled co-tenant IPs, and you have to validate each one before you call it C2.

The clearest example: `173.249.8.102` was decoded straight out of a resolver contract, which on a naive read makes it C2. It is not. The host runs a live, unrelated **Moroccan email-marketing/phishing kit** — a bilingual Laravel "ACADEMY" login whose support block names a separate operator entirely (`t.me/ouzougat`, a `+212` Moroccan number, `ouzougat@*` mailboxes). None of the EtherRAT fingerprints are present, and the page is *current* — so the Moroccan operator is the present occupant while the EtherRAT write was months earlier. Either a recycled shared VPS or a deliberate decoy; either way, not this actor.

The discipline that follows is simple and non-negotiable: every decoded indicator gets independently validated — by panel fingerprint, port profile, hosting, and timing — before it enters an IOC set. The contrast across two decoded IPs makes the point. `91.215.85.42` is triple-confirmed and goes in at high confidence; `173.249.8.102` is decoded from the same family and gets **excluded**. One confirmed, one ruled out, both from the same calldata. That an IOC set can do both is the difference between calibrated reporting and an inflated indicator dump — and it is exactly the trap that bulk-ingesting blockchain calldata sets for you.

## What this means — and what it doesn't

The temptation is to write the headline as "North Korea and Iran are collaborating." The evidence does not support that, and I want to weigh the hypotheses out loud.

- **H1 — one actor running both.** *Unlikely.* Disjoint operator and funding wallets, different deployment cadences, different hosting.
- **H2 — a direct DPRK–Iran operational partnership.** *Unlikely on current evidence, not excluded.* There is no on-chain coordination signal at all — no shared wallets, no cross-funding, no shared command infrastructure. Absence of an on-chain link is not proof of no off-chain contact, so I hold this open rather than refuting it.
- **H3 — a shared toolkit from a common (most likely Russian-speaking) MaaS builder, adopted independently.** *Most likely.* Identical bytecode and the shared event topic across clusters, eSentire's documented code overlap, Tsundere's koneko/CIS lineage, and the disjoint funding all point the same way.

The defensible conclusion is **shared supplier, independent customers**. Both North Korea and Iran are running this kit — that part is established at high confidence, on independent malware-family attribution for each. What is "most likely" rather than certain is only the *supplier's* identity: that the kit itself originates in the Russian-speaking criminal MaaS ecosystem. The two governments sourced C2 tradecraft from the same criminal market, the way they might both buy the same commercial exploit. When I hunted a direct koneko↔MuddyWater relationship in earlier work, the honest verdict was **ecosystem-level association only** — no shared identity, no shared command infrastructure, no dedicated money trail. That holds here.

Two more guardrails, because the data invites overreach. First: of the ~30 operator wallets on this kit, only two are plausibly state-aligned. The rest are most likely ordinary crimeware. A shared resolver family is the *opposite* of an attribution signal — it pools unrelated actors under one fingerprint, which is precisely why I make no operator-level nation attribution from the on-chain data alone. Second, and this is a strength rather than a caveat: the nation-state labels (DPRK, Iran) come from the **malware-family** attributions — DPRK on EtherRAT by Sysdig, eSentire and Atos plus convergent Contagious Interview tradecraft and crypto-theft victimology; Iran on MuddyWater/Tsundere by eSentire and Kaspersky — not from the contracts. Both labels are carried at **high confidence**. The on-chain kit tells you there is one builder and many buyers; it is the malware riding it, attributed independently and along multiple lines, that tells you two of those buyers carry flags.

## Why it matters

Two things, one tactical and one strategic.

Tactically, the immutability cuts both ways and defenders should exploit it. The operators chose a blockchain because it cannot be taken down. The same property means their entire C2 rotation history — every endpoint, every timestamp, every typo — is a permanent, queryable, free-to-read forensic record. You can enumerate a year of an actor's infrastructure from a laptop with no special access. I recovered Iranian C2 roughly seven months before it was publicly disclosed by reading events that were already, irreversibly, on the chain.

Strategically, this is a proliferation story. EtherHiding is no longer a North-Korea-only novelty; it is a commodity resolver kit that a Russian-speaking criminal market has put within reach of any operator willing to pay, and at least two state programs have picked it up. The line between nation-state tradecraft and criminal MaaS is not blurring — it has already dissolved at the tooling layer. Defend accordingly: assume the next actor on this kit may be neither of the two flags above.

## Detection — fingerprints over IPs

C2 endpoints on this kit rotate by design, so static C2 blocklists age out within the rotation window. Prioritize the durable signals:

- **Network — the resolver step.** Alert on internal hosts issuing `eth_call`-pattern HTTPS to multiple public Ethereum RPC providers (`blastapi.io`, `drpc.org`, `merkle.io`, `publicnode.com`, `tenderly.co`, `mevblocker.io`, `flashbots.net`) outside known developer/wallet activity. For most enterprises, anything talking to Ethereum RPC is anomalous and high-signal. This is the one network behavior EtherHiding cannot hide.
- **Network — the panel.** Hunt the `X-Bot-Server` CORS header on egress, and the co-hosting of ports `3000`/`3001` on a single host.
- **Endpoint.** `conhost.exe --headless` spawning `node.exe` from a user-writable path; `node.exe` running an `.xml` argument file or located under `...\Oracle\Java\javapath\`; new Run-key autostart pointing to randomly named binaries under `%APPDATA%\Local\<random>\`. Concrete artifacts from the sample I detonated: dropper `v9.msi` (`56058b92…`), resolver stage `cDQMlQAru0.xml` (`bbc4150d…`), helper files `_MJlLlt5.exe` and `KmPuGimn.cmd`, working directory `%APPDATA%\Local\2PhU26hCp7GZ\`, and TLS client fingerprints JA3 `30490d79325943f1ebf6750aae4e304c` and `d67b094811e5145139d7cea5f014309f`.
- **On-chain.** Hunt the `StringChanged` topic `0x3ca6280d…`; confirm family membership by bytecode selectors `7d434425`/`7fcaf666` plus the metadata hash `1de57633…`; pivot operator and deployer wallets to enumerate further contracts and the funding chain.
- **Containment reality.** You cannot take down the resolver. Containment is the endpoint (loader, persistence, Node stage) and the panel/RPC egress — not the contract.

Full IOC tables, the decompiled resolver, the funding walk, and the Suricata/Sigma/YARA/KQL pack are in the two repositories: the distributed-kit assessment at [`etherhiding-etherrat-kit`](https://github.com/yankywilson/etherhiding-etherrat-kit), and the DPRK/Iran shared-builder analysis with the live-C2 confirmation at [`etherrat-onchain-c2-detection`](https://github.com/yankywilson/etherrat-onchain-c2-detection). The Iranian-side family is at [`muddywater-etherhiding-resolver-family`](https://github.com/yankywilson/muddywater-etherhiding-resolver-family).

---

*Methodology: passive OSINT throughout, against an air-gapped standard — read-only block explorers, internet-scan data, and public sandbox reports. Two active touches (one cloud detonation, one liveness check) are disclosed in the repos. Confidence levels follow ICD-203 and are my own. Open thread: the newest, most active variant contract is still pending a full calldata decode, and the 24+9 family is enumerated but not exhaustively wallet-clustered — both are live work. TLP:CLEAR.*
