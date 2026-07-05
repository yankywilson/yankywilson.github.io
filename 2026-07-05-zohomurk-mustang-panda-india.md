---
layout: post
title: "ZOHOMURK & MINIRECON: Inside a Mustang Panda Cloud Dead-Drop Operation Against India"
date: 2026-07-05
author: Colonel Wilson
tags: [threat-intelligence, reverse-engineering, mustang-panda, zohomurk, minirecon, shardloader, apt, dfir]
description: "Independent reverse engineering of a June-2026 Mustang Panda toolkit that abuses Zoho WorkDrive as command-and-control against India's government and hydropower sectors."
---

## Executive summary

In June 2026 a China-nexus espionage actor — **Mustang Panda** (Earth Preta / TA416 / RedDelta / Bronze President / Twill Typhoon / Stately Taurus, MITRE **G0129**) — ran a targeted operation against **India's government and hydropower sectors**. The toolkit pairs a DLL-sideloading loader (**SHARDLOADER**) with two implants: **MINIRECON**, a Toneshell-derived backdoor beaconing over WebSocket-over-HTTPS, and **ZOHOMURK**, a novel implant that turns **Zoho WorkDrive into a dead-drop command channel** using hardcoded OAuth credentials.

This analysis was performed **independently**, roughly four days after Acronis TRU published the campaign, and **without knowledge of that report at the time**. Findings that overlap with Acronis are noted as **independent verification**; findings absent from public reporting are flagged as **novel**.

Full technical repository, IOCs, YARA/Sigma, and a TLS session decryptor:
**https://github.com/yankywilson/zohomurk-mustang-panda-analysis**

> **Bottom line.** The command channel is a legitimate cloud service. There is no attacker domain or IP to block — defense is behavioural: catch the signed-binary sideload and the OAuth/WorkDrive activity from non-browser processes.

---

## The operation

Two parallel campaigns, one operator, both delivered by spear-phishing ZIPs hiding a malicious DLL beside a **signed** launcher:

| | Campaign I | Campaign II |
|---|---|---|
| Implant | MINIRECON (Toneshell-derived) | ZOHOMURK (`ctxmui.dll`) |
| C2 model | WebSocket-over-HTTPS | Zoho WorkDrive dead-drop (OAuth) |
| Signed host | Solid PDF Creator | Citrix `pcl2bmp.exe` |
| Lure | Hydropower Cooperation Project Proposal | MOU (India–Taiwan) archive |
| Infrastructure | operator domains + cert cluster | **none — abuses Zoho only** |

---

## SHARDLOADER — the loader

A DLL delivered hidden in the ZIP and sideloaded through a signed host binary. It reconstructs and decrypts a payload and launches the implant.

- **Inline RC4 key** in `.rdata`: `urt!@#ghsiet63540(mk)?78Xdesr*%rt$36` — the single strongest cluster anchor. **(novel)**
- Export `GetSPApp`; a run-once execution guard; a TLS callback that runs anti-analysis checks before `DllMain`.
- Campaign I variant reconstructs fragmented shellcode from `.rdata`, decrypts with rolling-XOR + byte-reorder, and executes via an `EnumSystemLocalesA` callback.

---

## ZOHOMURK — cloud dead-drop implant

ZOHOMURK masquerades as Citrix `ctxmui.dll` and uses **Zoho WorkDrive as its entire C2**. The design is an eight-function loop:

1. POST a hardcoded `grant_type=refresh_token` bundle to `accounts.zoho.com/oauth/v2/token`.
2. Inject the returned token as `Authorization: Zoho-oauthtoken`.
3. Poll a WorkDrive **inbox** folder for a task file (`cmd.dat`).
4. Execute it through a headless `cmd.exe`.
5. Upload results (`cmd.out_*`) to an **outbox** folder.

Traffic uses **seven fake Zoho User-Agents** (`Zoho Client/1.0`, `Zoho-C-Uploader/2.0`, `Zoho-C-Downloader/1.1`, `Zoho API C-Client/1.0`, and variants) with correct content types — so it blends into normal SaaS use. The tell is the **UA-vs-process mismatch**: Zoho user-agents from a non-browser process. **(novel — full set)**

### Two builds, one operator

Two distinct `ctxmui.dll` builds were reverse-engineered:

| | Build 1 (`f2bed071…`) | Build 2 (`5f22ec5c…`) |
|---|---|---|
| Export(s) | `CTXMUI_ParseArgvA` | `CTXMUI_FormatMessageW` / `…LoadResourceLibraryW` |
| imphash | `40113fcd…` | `5c3561878ba749648363ffd4499398b2` |
| Named event | `Local\MS_Edge_Update_Task_Service_Sync` | `ZohoUsingUpdataAnyssAll_event` |
| Zoho account | client_id `1000.C7Z2WGQR…` | client_id `1000.1MJOH90…` |

The two builds use **entirely different Zoho accounts** (distinct client_id, secret, refresh token, folder namespaces) — but share author markers: the internal name `Project5.dll`, a keyboard-mash PDB string, the misspelling **`RunOnece`** in the persistence value, and the identical fake-UA set. Assessed **same operator running compartmentalized C2 accounts** — resilience tradecraft so one takedown does not burn the other. **(novel)**

### Persistence & proxy execution (build 2)

Self-installs to `%LOCALAPPDATA%\ctxmui.dll`, sets an HKCU Run value `ZohoUsingUpdataAnyssAll_RunOnece`, and drops the **legitimate** Windows `rundll32.exe` into `%LOCALAPPDATA%\ZohoUsing\` to proxy the implant (T1218.011). The dropped `rundll32.exe` is a clean binary — flagged only for its anomalous location. **(novel)**

---

## MINIRECON — Campaign I

A **Toneshell-derived** implant delivered by SHARDLOADER v1.0. It keeps Toneshell hallmarks (PEB-walking API resolution, the `13131313` hashing multiplier, an LCG session-key scheme) and adds a bespoke **C++ WinHTTP WebSocket** C2 that disables certificate validation and falls back through proxies. Crypto is an **LCG-seeded XOR keystream** (multiplier `0xBD828`, increment `0x4373A`), with a ~45-second beacon and temp-file timing sandbox evasion. **(novel — constants)**

The Campaign I cluster is anchored by a **self-signed certificate** (`41b59aca…`, `CN=localhost`) and a shared registrant token (`37bfbc24…`) across three operator domains, with a netblock overlap (AS132335) tying to prior Hive0154 reporting.

---

## Dynamic proof: the C2 was already dead

Detonating build 2 (2 and 5 July 2026) and **decrypting the TLS 1.2 session** (the sandbox capture embedded a key log) returned plaintext OAuth responses of `{"error":"inactive_client"}` and WorkDrive `401 Unauthorized`. Both operator OAuth applications were **deactivated** — assessed as a takedown after the late-June disclosure. The implant's OAuth loop has **no client-side rate limiting**, so it self-throttled into provider `429`/`Access Denied` — itself a useful hunting signal. **(novel)**

A false-positive worth flagging: a legitimate Solid PDF Creator host EXE ships alongside the malware and must not be treated as an IOC — verify file identity before clustering.

---

## Attribution

**Mustang Panda (G0129), China-nexus — MODERATE confidence.** The assessment leans on a single primary vendor for the campaign but is independently verified at the sample and technique level. The two-build / one-operator link is carried by first-party author markers. The Zoho WorkDrive dead-drop technique has an **APT37 / RESTLEAF** precedent — recorded as **technique convergence, not an operator bridge.**

---

## Detection guidance

- **Registry:** Run value `ZohoUsingUpdataAnyssAll_RunOnece` (or any `ZohoUsing*` / `RunOnece` name).
- **Process:** `rundll32.exe` running from `%LOCALAPPDATA%\ZohoUsing\`.
- **Network:** OAuth token grant to `accounts.zoho.com/oauth/v2/token` followed by WorkDrive calls carrying `Zoho-oauthtoken`, **from a non-browser process**; fake Zoho user-agents.
- **Behavioural:** a burst of OAuth token requests (dozens/minute) from one process; no-ALPN WinHTTP JA3 `2800f914a7a4ba98aa9df62d316a460c` to Zoho hosts.
- **Do not** block or pivot shared Zoho hosts/IPs org-wide — scope every rule to process context.

YARA (SHARDLOADER RC4 + both `ctxmui` builds + author markers), a five-rule Sigma pack, the full IOC set, and a TLS session decryptor are in the repository.

---

## Key indicators

| Indicator | Meaning |
|---|---|
| `5f22ec5c…` / `f2bed071…` | ZOHOMURK `ctxmui.dll` builds 2 / 1 |
| `a43084f5…` | SHARDLOADER |
| imphash `5c3561878ba749648363ffd4499398b2` | ZOHOMURK build 2 cluster |
| RC4 key `urt!@#ghsiet63540(mk)?78Xdesr*%rt$36` | SHARDLOADER |
| Run value `ZohoUsingUpdataAnyssAll_RunOnece` | persistence |
| JA3 `2800f914a7a4ba98aa9df62d316a460c` | WinHTTP C2 (no-ALPN) |
| cert `41b59aca…` + `couldinstallup[.]com` | MINIRECON cluster |

**Full IOCs, detections, and tooling:** https://github.com/yankywilson/zohomurk-mustang-panda-analysis

---

*Independent defensive research. TLP:CLEAR. Shared to help defenders detect and remediate this activity. Recovered operator credentials are withheld from public material and routed only to Zoho Trust & Safety and CERT-In for takedown.*
