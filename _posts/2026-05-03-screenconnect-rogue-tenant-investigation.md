---
layout: post
title: "From a phishing PCAP to the OSINT ceiling: investigating a rogue ConnectWise ScreenConnect operator"
date: 2026-05-03 12:00:00 -0400
categories: [threat-intelligence, malware-analysis]
tags: [screenconnect, rogue-rmm, clickfix, osint, attribution, detection]
excerpt: >-
  An independent investigation of a rogue ConnectWise ScreenConnect tenant
  abuse campaign — from a single phishing PCAP through MSI reverse engineering,
  cross-jurisdiction infrastructure mapping, a novel network detection signature,
  and the OSINT attribution ceiling that always exists for careful commodity operators.
---

This is the narrative version of an investigation I ran into an active rogue ConnectWise ScreenConnect tenant abuse campaign. The full case file (21-page PDF, detection rules, defanged IOCs) lives on [GitHub]({{ "/" | absolute_url }}) at [yankywilson/screenconnect-rogue-tenant-investigation](https://github.com/yankywilson/screenconnect-rogue-tenant-investigation). This post is the human-readable version of how it actually unfolded.

---

## The starting point: a single phishing PCAP

The investigation started with one captured network trace from a fake Microsoft Teams update phishing chain. The chain looked simple at first:

1. A Microsoft Teams-themed phishing email pointed victims to an AWS S3-hosted page (`teams[.]live`)
2. The page used **ClickFix-style social engineering** — instructions telling the victim to paste a command into the Windows Run dialog "to verify your meeting"
3. The pasted command silently downloaded a ConnectWise ScreenConnect MSI installer from `documentsharefiles[.]com`
4. Once installed, the ScreenConnect client connected back to a malicious tenant the operator controlled, granting them full graphical remote access to the victim's machine

That last step is the punchline. **ConnectWise ScreenConnect is a legitimate enterprise remote-management product.** The operator wasn't writing custom malware — they were paying for a SaaS subscription to a real commercial product and pointing victims' machines at their own tenant. From the victim's perspective, `ScreenConnect.ClientService.exe` is a signed, legitimate Microsoft-tolerated process. From the operator's perspective, it's a free RAT with built-in remote desktop, file transfer, and command execution.

This is the rogue-RMM-tenant pattern that Huntress and NCC Group have been documenting throughout 2025 and 2026. I wanted to know: who specifically is running this tenant?

## Reverse engineering the MSI

The ScreenConnect MSI installer is what links a victim to a specific operator. Each tenant gets a unique installer with embedded identifiers — tenant alias, GUIDs, ProductCode, UpgradeCode, an RSA public key for encrypted communication, and (interestingly) operator-chosen "session tags" used for workflow labeling.

For the spg0rz tenant, I extracted:

- Client GUID `6d9112a230e18c81`
- ProductCode `{E566EEBD-3A56-03C1-0180-A294D8C484CA}`
- Session tag `c=Mash` — operator's chosen workflow label

That last one is interesting because it's operator-supplied. `Mash` is whatever the operator decided to call this campaign in their own tenant management UI. Other siblings in the same kit family used `c=NEWBEGINNING`. These are weak handles but they're handles.

## The OSINT spiral

From the MSI fingerprints, I pivoted across roughly fifteen platforms:

- **VirusTotal** for hash and URL reputation
- **urlscan.io** for historical lure renders
- **ANY.RUN** for sibling tenant enumeration through cross-corpus search
- **Recorded Future Triage** for behavioral detonation
- **Joe Sandbox** for additional sample analysis
- **Censys** and **Validin** for infrastructure pivots
- **MalwareBazaar** and **abuse.ch ThreatFox** for sample distribution data

Each platform contributed something. ANY.RUN surfaced four additional sibling tenants. Censys identified the operator's MSI distribution server in Russia. Triage captured live behavioral data showing the ScreenConnect process making a *separate* C2 callout to `i8reactorsee[.]xyz` in Romania — independent of the primary ScreenConnect relay. This second host was operator-controlled too.

I now had three correlated operator hosts across three jurisdictions:

- The MSI distribution server `5[.]8[.]11[.]68` (Russia, PINDC-AS)
- The secondary C2 `i8reactorsee[.]xyz` at `85[.]122[.]114[.]130` (Romania)
- The ScreenConnect tenant relay on the OVH SaaS shard at `15[.]204[.]43[.]236`

## The single biggest OPSEC failure

The Russian MSI distribution server had an **exposed `phpinfo()` page** at `/info.php`. The operator forgot to delete it after using it to verify their PHP install was working.

`phpinfo()` is a PHP debugging function that dumps the entire server configuration to a webpage. In this case it leaked:

- The hosting reseller hostname: `s125671[.]bpwhost[.]com`
- The exact server software stack
- Apache and PHP version numbers
- The full Linux environment

That hostname is the OPSEC failure. **`s125671` is the operator's customer ID at BPW Host**, a small European VPS reseller. BPW Host is the layer between the operator and the upstream Russian datacenter — which means BPW Host knows who the operator is. Their customer record contains the operator's payment method, contact email, and signup IP.

This was the closest thing to a "real lead" the entire investigation produced. Not because BPW Host's records are public — they're not — but because they exist, and they're reachable through legal process. Subpoena-only, but reachable.

## A genuinely novel detection finding

While analyzing PCAPs of the c3g0hr tenant talking to its ScreenConnect relay, I noticed something I'd never seen documented: **the ScreenConnect relay protocol on TCP/443 is not TLS.**

It's a custom ConnectWise binary protocol. The first packet from the client to the relay starts with magic bytes `\x87\x1e\x10\x00` followed by a length-prefixed plaintext ASCII string carrying the tenant alias.

```
First packet, c2s direction:
  \x87\x1e\x10\x00 ...
  (length byte) 'instance-c3g0hr-relay.screenconnect.com'  (40 bytes ASCII plaintext)
  ... encrypted session payload ...
```

This means a network IDS sees the tenant alias on the wire **without TLS interception**. Pair the magic-byte signature with a tenant-alias allowlist of legitimate customer tenants, and you have a high-fidelity rogue-RMM-tenant detection that works against the entire ScreenConnect kit family — not just one operator.

Working Suricata and Sigma rules for this are in the [investigation repo](https://github.com/yankywilson/screenconnect-rogue-tenant-investigation/tree/main/detection-rules).

## The attribution wall

After 15+ platforms and several days of investigation, here is what I could honestly say about the operator:

- **Russian-speaking** (direct Russian hosting + vendor reporting convergence)
- **Commodity-tier kit buyer**, not the kit author
- **Probably an Initial Access Broker** reselling installs to ransomware affiliates
- **Mid-tier OPSEC** — careful in some places, careless in others
- **Active since at least October 2025**

What I could **not** say:

- A specific person's name
- A specific country more precise than "Russian-speaking"
- A specific named threat group (Storm-1175, Akira, FIN7, etc. — none of these match)
- Specific downstream consumers

This is the **OSINT attribution ceiling for commodity-tier operators with basic OPSEC.** It's reached in the majority of independent investigations of similar campaigns. Mandiant, CrowdStrike, and Recorded Future routinely publish reports that end at this same wall.

The operator's identity exists in five places, all behind legal process:

1. ConnectWise tenant signup data
2. BPW Host customer record (s125671)
3. Domain registrar records for `documentsharefiles[.]com`
4. The VPN provider's logs (if they exist at all)
5. PINDC-AS subscriber data (in Russia, effectively unreachable)

OSINT cannot bridge that gap. This is by design — commodity operators with basic OPSEC are specifically engineered to be unfindable through open sources. If they were findable, they wouldn't still be in business.

## What I did instead of giving up

The instinct when you hit the OSINT wall is to keep searching. The honest move is to **stop and use the wall to your advantage** — meaning: file abuse reports against every infrastructure layer, on the theory that legal process is the only thing that bridges the wall, and abuse reports are the public-facing input to that process.

I filed (or drafted, where pending):

- **ConnectWise security** — to suspend the rogue tenant `c3g0hr`
- **BPW Host abuse** — to suspend the customer hosting the MSI server
- **AWS abuse** — to remove the S3-hosted phishing page
- **Dropbox abuse** — to remove the dropper share
- **Huntress tradecraft** — researcher-to-researcher contact, contributing data on the kit family
- **NCC Group CIRT** — same, with timing alignment to their October 2025 reporting
- **FBI IC3** — the only path with subpoena power, formal complaint pending

In the time between the start of the investigation and now, **the campaign has begun to collapse on its own**. The lure domain `documentsharefiles[.]com` is now NXDOMAIN at the registry level. The secondary C2 `i8reactorsee[.]xyz` has been sinkholed. Two pieces remain live as of this writing — the c3g0hr ScreenConnect tenant and the Russian MSI distribution server — and abuse reports against both are filed.

## Honest calibrations

A professional CTI report has to acknowledge where earlier interpretations were wrong. Three corrections from this investigation:

**1. The "operator visit" interpretation was wrong.** Earlier in the investigation, the exposed `phpinfo()` leaked a visitor IP that I initially read as a likely operator visit through commercial VPN. A re-detonation showed the visitor IPs were Recorded Future Triage's sandbox egress, not the operator. There is **no signal of operator self-visits** in the data.

**2. The "QuickBooks fraud" signal was browser noise.** Initial PCAP analysis surfaced traffic to Intuit / online-metrix endpoints that I initially read as evidence of QuickBooks-targeted fraud. Closer analysis showed this was the sandbox VM's Edge browser making routine Intuit telemetry connections, not operator C2.

**3. PINDC-AS is not bulletproof hosting.** Early framing characterized it as plausibly operator-curated. Censys enumeration showed legitimate Russian infrastructure (Yandex Linux mirror) in the same ASN. PINDC is just generic Russian hosting.

These corrections are documented in the report rather than hidden. This is what calibration looks like — and it's what separates credible analyst work from hype.

## The takeaway

Independent OSINT against a careful commodity operator does not produce a name. It does produce:

- A complete kill chain
- A mapped infrastructure surface
- Operator OPSEC profiling
- Detection signatures that work at the kit-family level
- Coordinated disruption of the campaign through abuse channels

That's a complete investigation. The fact that it ends without a name isn't a failure — it's what the data supports.

If you're another researcher tracking this kit family, all of the [IOCs](https://github.com/yankywilson/screenconnect-rogue-tenant-investigation/tree/main/iocs) and [detection rules](https://github.com/yankywilson/screenconnect-rogue-tenant-investigation/tree/main/detection-rules) in the repo are open for community use. If you build on this work, attribution is appreciated but not required. If you spot a correction or have additional indicators, please open an issue.

---

**Read the full case file:** [GitHub repo](https://github.com/yankywilson/screenconnect-rogue-tenant-investigation) (PDF + Suricata/Sigma rules + IOC CSV)
