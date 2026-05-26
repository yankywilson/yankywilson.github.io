---
title: "UAC-0241 / GAMYBEAR threat brief: targeting, TTPs, IOCs and hunting guidance for CTI teams"
date: 2026-05-27 14:00:00 +0000
categories: [Threat Briefs]
tags: [threat-intelligence, uac-0241, gamybear, cert-ua, russia-ukraine, apt, ioc, hunting, detection-engineering, mitre-attack]
description: "A threat intelligence brief on UAC-0241 and the GAMYBEAR backdoor based on independent binary analysis and CERT-UA's incident response findings. Includes targeting profile, kill chain reconstruction, MITRE ATT&CK mapping with binary-vs-IR labeling, consolidated IOCs, hunting queries for KQL, SPL and Sigma, variant tracking guidance and intelligence gaps."
---

This is the companion threat intelligence brief to my [GAMYBEAR reverse engineering writeup](https://yankywilson.github.io/2026/05/26/gamybear-uac-0241-investigation/). The RE post is the narrative version of how the investigation unfolded. This post is the analyst-facing reference product: BLUF, key judgments, kill chain mapping, IOCs, hunting queries, intelligence gaps. Use whichever serves the work.

Confidence levels throughout follow ICD-203 conventions (HIGH / MODERATE / LOW). Findings are labeled **(binary)** where derived from my own reverse engineering, **(CERT-UA)** where derived from CERT-UA's incident response advisory, and **(inferential)** where logically required by observed facts but not directly verified.

---

## Bottom line up front

UAC-0241 is a Russian-aligned intrusion set tracked by CERT-UA, targeting Ukrainian education and state authority entities with the GAMYBEAR Go-language backdoor and supporting tooling (LaZagne credential dumper, RESOCKS SOCKS proxy). The GAMYBEAR binary contains a Go default HTTP client TLS-validation behavior that renders the malware non-functional in any clean Windows environment where the operator's certificate authority has not been pre-installed, producing a hash-independent network detection signature against the entire kit family. The intrusion set's tradecraft profile is mixed: file-level OPSEC is poor (unstripped DWARF, operator persona strings embedded in the binary, plaintext config) while infrastructure-level OPSEC is more disciplined (scanner-invisible C2 port 443, cert template camouflaged in Russian-language commercial hosting noise). I assess with **MODERATE confidence** that the team continues to iterate the tooling and that future variants will address the TLS flaw, in which case the network detection content stops working and the host-side cert-install detection becomes the higher-leverage signal.

---

## Key judgments

- **HIGH confidence (binary):** The GAMYBEAR binary uses Go's `net/http.DefaultClient` without TLS configuration override. The default client performs strict chain validation against the OS trust store with no bypass. The bot cannot complete a TLS handshake to its C2 server (which presents a self-signed certificate) on any Windows host without operator-side CA pre-installation. Verified through static reverse engineering, PCAP analysis, and live dynamic detonation over 60+ minutes.

- **HIGH confidence (binary):** GAMYBEAR's only host-side persistence artifact is the JSON identity file at `%APPDATA%\updater.json`. The binary contains no registry-modification API calls in its import table and no registry-related symbols in its function table. Registry autorun persistence attributed to the family in some advisory content is performed by the upstream PowerShell stage, not by the GAMYBEAR binary itself.

- **MODERATE confidence (inferential):** The upstream `updater.ps1` PowerShell stage installs the operator-controlled CA certificate into the Windows trust store before launching the GAMYBEAR binary. This is logically required by the binary's behavior (without the CA install, the bot is inert) and matches CERT-UA's documented kill chain, but the PowerShell stage has not been directly analyzed in this investigation. Confidence would upgrade to HIGH on direct PS1 analysis.

- **MODERATE confidence (binary + CERT-UA):** UAC-0241 has operational adjacency to the Gamaredon intrusion set (CERT-UA tracking ID UAC-0010). The basis is the `gamaredagne.py` filename (portmanteau of Gamaredon + LaZagne) appearing in CERT-UA's broader IOC list, shared Ukrainian education-sector targeting, and Russian-aligned attribution. Whether UAC-0241 is a Gamaredon sub-cluster, a parallel team, or unrelated tooling sharing targets remains an open question.

- **MODERATE confidence (binary + open source):** The GAMYBEAR developer continues to iterate the tooling. Two variant filenames (svshosts.exe and ieupdater.exe) are documented in CERT-UA's advisory, indicating at least one rebuild between observed deployments. The unanalyzed ieupdater.exe variant is the highest-value follow-up artifact for variant comparison.

- **LOW confidence (binary):** The Moscow-themed certificate subject (`CN=cloudflare-dns.com, L=Moscow, ST=Moscow, C=RU`) is operator misdirection planted to mislead attribution rather than operational candor. Two interpretations fit the evidence equally: (a) operator confidence with no need to hide attribution, (b) deliberate planting of attribution markers. Distinguishing these requires operator-side access this investigation does not have.

---

## Threat actor profile: UAC-0241

| Attribute | Value | Source |
| --- | --- | --- |
| Tracking ID (primary) | UAC-0241 | CERT-UA |
| Aliases | None publicly documented as of analysis date | Open source |
| Attribution | Russian-aligned | CERT-UA |
| Motivation | Espionage assessed; no destructive activity observed | Inferential |
| MITRE ATT&CK Groups entry | None as of analysis date | MITRE |
| ETDA threat group encyclopedia | No entry | ETDA |
| Adjacency | Possible relationship to Gamaredon (UAC-0010) | Inferential |
| First public disclosure | 2025-11-18 (CERT-UA#18329) | CERT-UA |
| Earliest infrastructure provisioning | 2025-04-27 (C2 cert NotBefore) | binary / PCAP |
| Earliest documented intrusion | 2025-05-26 (Sumy university Gmail compromise) | CERT-UA |
| Public binary-level coverage prior to my work | None | Open source |

Western vendor coverage of this intrusion set was minimal as of analysis date. The only public source of intelligence on UAC-0241 is CERT-UA's advisory plus brief reference paragraphs in security press citing CERT-UA. The cluster has not been formally tracked by Mandiant, CrowdStrike, Recorded Future, or other major commercial threat intelligence vendors in their public reporting.

The Gamaredon adjacency is suggestive but not definitive. Gamaredon (also tracked as Primitive Bear, Shuckworm, and Aqua Blizzard depending on vendor) is a long-running Russian FSB-attributed group with extensive documented activity against Ukrainian targets. The shared targeting profile, the `gamaredagne.py` portmanteau in IOC artifacts, and the Russian-aligned attribution all point in the same direction, but tradecraft differences between mature Gamaredon tooling and the developmentally-immature GAMYBEAR backdoor argue against direct authorship sharing. UAC-0241 may be a Gamaredon-adjacent team, a contractor relationship, or coincidentally overlapping targeting.

---

## Campaign overview

| Attribute | Value | Source |
| --- | --- | --- |
| Primary targeting | Ukrainian education and state authority entities | CERT-UA |
| Documented geography | Sumy oblast; broader Ukraine implied | CERT-UA |
| Documented sectors | Universities, state authorities | CERT-UA |
| Initial access vector | Compromised Gmail account (no MFA) used to send phishing | CERT-UA |
| Documented earliest victim | Sumy oblast university | CERT-UA |
| Campaign timeframe (observed) | 2025-05-26 through 2025-11-18+ (likely ongoing) | CERT-UA |
| C2 IP (primary) | 185[.]223[.]93[.]102 (AS14576 HOSTING-SOLUTIONS, Amsterdam-claimed) | binary / PCAP |
| Related infrastructure (additional IPs) | 136[.]0[.]141[.]69, 45[.]159[.]189[.]85, 62[.]182[.]84[.]66 | CERT-UA |
| Related domain | grizzlyconnect[.]net (and subdomain testnl[.]grizzlyconnect[.]net) | CERT-UA |
| Documented payload set | GAMYBEAR, LaZagne, RESOCKS | CERT-UA + binary |
| Disclosure status | Publicly disclosed by CERT-UA 2025-11-18 | CERT-UA |

The intrusion set's targeting in the documented campaign is narrow (Ukrainian government and education) and consistent with Russian-aligned strategic interest. No commercial or financial targeting has been observed. No destructive activity has been documented; the intrusion set's documented tooling (RAT + credential dumper + SOCKS proxy) is consistent with espionage-oriented operations including credential theft, lateral movement, and persistent access for collection. Whether collected data exfiltrates through the RESOCKS proxy infrastructure or through the GAMYBEAR C2 channel is not clearly documented in public reporting.

---

## Kill chain reconstruction

The full kill chain documented by CERT-UA, with phases each team component executes. Mappings labeled by evidence source.

```
[Initial Access]                      [Execution]                        [Defense Evasion]
Compromised Gmail (no MFA)            User opens .lnk                     PowerShell drops CA cert
  ↓                                     ↓                                   to Windows trust store
Phishing email + ZIP attachment       mshta.exe → zvit.hta                  ↓
  ↓                                     ↓                                 GAMYBEAR uses signed-by-
[Delivery]                            update.js                           operator-CA HTTPS C2
.lnk shortcut file                      ↓                                
  ↓                                   updater.ps1
[Execution kickoff]                     ↓
                                      Drops:
                                        - svshosts.exe (GAMYBEAR)
                                        - LaZagne (credential dumper)
                                        - RESOCKS (SOCKS proxy)
                                        - (writes HKCU Run autorun)
```

**Phase 1: Initial access (CERT-UA)**

The operator obtained access to a Sumy oblast university Gmail account, observed by CERT-UA as having no multi-factor authentication enabled. The compromise method itself is not specified in the advisory but the absence of MFA is identified as the enabling condition. The compromised account was then used to send phishing emails to additional targets, leveraging the trusted-sender reputation of the university's legitimate user.

**Phase 2: Delivery (CERT-UA)**

Phishing emails carried ZIP attachments containing a Windows shortcut (`.lnk`) file. The shortcut's command line invoked `mshta.exe` (Microsoft HTML Application host, a signed Windows utility) to retrieve and execute a remote HTA file (`zvit.hta`). HTA-via-LNK delivery is a well-established living-off-the-land technique that bypasses some attachment-scanning policies because the LNK itself contains no executable code, only a command line.

**Phase 3: Execution chain (CERT-UA)**

`mshta.exe` executed `zvit.hta`, which contained JavaScript loading `update.js`. The JavaScript stage invoked PowerShell to retrieve and execute `updater.ps1`. The PowerShell stage performed several actions in sequence:

- Dropped the GAMYBEAR Go binary (filename varies: `svshosts.exe` or `ieupdater.exe`) to a path under `%APPDATA%`
- Dropped the LaZagne credential-dumping utility (likely as `gamaredagne.py` based on naming pattern)
- Dropped the RESOCKS SOCKS proxy binary
- Wrote a registry autorun entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` pointing to the dropped GAMYBEAR binary
- **(Inferential)** Installed the operator's CA certificate into the Windows trust store, enabling the GAMYBEAR binary's TLS validation against the C2 server's self-signed certificate
- Launched the GAMYBEAR binary

**Phase 4: GAMYBEAR execution (binary)**

The GAMYBEAR binary, on first run, performs the following operations:

- Generates a UUIDv4 identifier using the `github.com/google/uuid` library
- Collects hostname via `whoami.exe` stdout, base64-encoded with trailing CRLF preserved (base64 suffix `DQo=` is consistent)
- Collects IP via `wmic nicconfig get IPAddress`, base64-encoded (empty on Windows 11 22H2+ where wmic.exe has been removed)
- Writes identity record to `%APPDATA%\updater.json` as `{update_server, uuid, hostname, ip}`
- POSTs registration beacon to `https://185[.]223[.]93[.]102/register` with body `{uuid, hostname, ip_address}`
- Enters command-poll loop: GET `https://185[.]223[.]93[.]102/c2/get_commands/<UUID>` every 15 seconds (5 seconds on error)
- On non-Nop command receipt, executes via `exec.Command` with `HideWindow:true` (direct CreateProcessW, no shell)
- POSTs result to `https://185[.]223[.]93[.]102/c2/command_out/<UUID>` with body `{uuid, command, output}` (output base64-encoded)

**Phase 5: Post-exploitation tooling (CERT-UA)**

- **LaZagne (`gamaredagne.py`):** Open-source Python-based credential-recovery tool, repurposed for offensive credential extraction across browsers, mail clients and system stores.
- **RESOCKS:** SOCKS5 proxy tool enabling traffic tunneling through the compromised host. Likely used for lateral movement and additional access from operator-controlled infrastructure.

---

## MITRE ATT&CK mapping

The following techniques are observed across the full UAC-0241 kill chain. Each is labeled as binary-derived (recovered from my reverse engineering of GAMYBEAR), CERT-UA-derived (from the advisory's documentation of the broader chain), or inferential (logically required but not directly verified).

| Technique ID | Technique name | Phase | Source |
| --- | --- | --- | --- |
| T1078 | Valid Accounts | Initial Access | CERT-UA |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | CERT-UA |
| T1204.002 | User Execution: Malicious File | Execution | CERT-UA |
| T1218.005 | Signed Binary Proxy Execution: Mshta | Defense Evasion / Execution | CERT-UA |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | CERT-UA |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution | CERT-UA |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence | CERT-UA (performed by PowerShell stage, **not** by GAMYBEAR binary per binary analysis) |
| T1553.004 | Subvert Trust Controls: Install Root Certificate | Defense Evasion | Inferential (required by binary behavior, performed by PowerShell stage) |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | binary (base64 of beacon data) |
| T1033 | System Owner/User Discovery | Discovery | binary (whoami) |
| T1016 | System Network Configuration Discovery | Discovery | binary (wmic, fails on Win11 22H2+) |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | binary (HTTPS to /register, /c2/get_commands/, /c2/command_out/) |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control | binary (TLS, brittle due to default-client validation) |
| T1132.001 | Data Encoding: Standard Encoding | Command and Control | binary (base64 of stdout + hostname + IP) |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | binary (command output exfiltrated via /c2/command_out/) |
| T1555 | Credentials from Password Stores | Credential Access | CERT-UA (LaZagne) |
| T1090 | Proxy | Command and Control | CERT-UA (RESOCKS) |

**Notable mapping considerations.** T1547.001 (Registry Run Keys) is the technique most likely to produce detection-engineering false negatives if attributed to the wrong process. CERT-UA's advisory describes this technique as observed in the kill chain, which is correct at the kill-chain level. Binary analysis confirms the GAMYBEAR binary itself does not perform this technique — it is performed by the upstream PowerShell stage. Detection content keying on the GAMYBEAR process names (svshosts.exe, ieupdater.exe) writing to Run keys will not fire. Detection content keying on powershell.exe writing to Run keys with a target value pointing into `%APPDATA%` will fire.

T1553.004 (Install Root Certificate) is currently labeled inferential because the PowerShell stage has not been analyzed directly. Upgrading this to a verified mapping requires direct analysis of `updater.ps1`. If verified, this would be the single highest-leverage detection point in the kill chain because the technique is rarely performed by legitimate enterprise software in non-administrative contexts.

---

## Indicators of compromise

All IOCs defanged for safe handling. Verified accuracy as of 2026-05-26. Live status of network indicators not separately confirmed.

### File hashes

| Type | SHA-256 | Description | Source |
| --- | --- | --- | --- |
| GAMYBEAR | `f4cfbd86609b558a76e43a8da7a47b211d4c498d1167b65bf43aa199e4a252fd` | svshosts.exe variant — fully analyzed in this work | binary |
| GAMYBEAR | `5d3f5d174369b34c436df0ad467236bd477b12b817768e19113969e08d74ef5d` | ieupdater.exe variant — **not analyzed**, follow-up priority | CERT-UA |
| LaZagne | `b1f71dd2e152d46cc0c423cfe563c9215182dc68afdca7b0a19c134ef9f0895e` | Credential-dumping utility (likely `gamaredagne.py` or compiled form) | CERT-UA |
| RESOCKS | `550fc52e7adcdf237666a7e3cb324e8f71f7ca1cd6cd3b681e44a337d4ba4d66` | SOCKS5 proxy | CERT-UA |

### Network indicators

| Type | Value | Description | Source |
| --- | --- | --- | --- |
| IPv4 | `185[.]223[.]93[.]102` | GAMYBEAR C2 (AS14576 HOSTING-SOLUTIONS BV, Amsterdam-claimed) | binary / PCAP |
| IPv4 | `136[.]0[.]141[.]69` | Additional UAC-0241 infrastructure | CERT-UA |
| IPv4 | `45[.]159[.]189[.]85` | Additional UAC-0241 infrastructure | CERT-UA |
| IPv4 | `62[.]182[.]84[.]66` | Additional UAC-0241 infrastructure | CERT-UA |
| Domain | `grizzlyconnect[.]net` | UAC-0241 domain | CERT-UA |
| Domain | `testnl[.]grizzlyconnect[.]net` | UAC-0241 subdomain | CERT-UA |
| Email | `sumy[.]dsns[.]gov[.]ua@gmail[.]com` | Compromised Gmail used for initial delivery | CERT-UA |
| URL path | `/register` | GAMYBEAR registration endpoint | binary |
| URL path | `/c2/get_commands/<UUIDv4>` | GAMYBEAR command poll endpoint | binary |
| URL path | `/c2/command_out/<UUIDv4>` | GAMYBEAR result submission endpoint | binary |

### TLS / certificate forensics

| Field | Value | Source |
| --- | --- | --- |
| C2 cert SHA-256 | `0c954b885bfeabc3da8dc9a8629399a9de3ad75c703a2de4c3828d390cc24e7a` | PCAP |
| C2 cert SHA-1 | `c0afb91b46bcdcd0f2a69f50fa81215eceafe7d4` | PCAP |
| C2 cert SPKI SHA-256 | `9c1daf9ddc8eae8a87def79e7e451e041ffb9daea7742b36c5fd517c50dadaf7` | PCAP |
| C2 cert serial | `0x75ffd826eb99b28abaed15aa0cb7d3517242b058` | PCAP |
| C2 cert subject DN | `CN=cloudflare-dns.com, O=Company Ltd, L=Moscow, ST=Moscow, C=RU` | PCAP |
| C2 cert validity | 2025-04-27 through 2026-04-27 | PCAP |
| Client JA3 | `397c55c9aaf9820f7655666ee7fc3c2d` (matches default Go crypto/tls) | PCAP |
| Client JA4 | `t13i1910h2_9dc949149365_e7c285222651` | PCAP |
| Failure-mode alert | TLS Alert(level=Fatal, description=bad_certificate=42) | PCAP / detonation |

### Host indicators

| Type | Value | Description | Source |
| --- | --- | --- | --- |
| File path | `%APPDATA%\updater.json` | GAMYBEAR identity/persistence file (binary-created) | binary |
| File name | `svshosts.exe` | GAMYBEAR variant filename | CERT-UA |
| File name | `ieupdater.exe` | GAMYBEAR variant filename | CERT-UA |
| Registry path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Autorun key (written by PowerShell stage, **not** by GAMYBEAR binary) | CERT-UA + binary |
| Registry path | `HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\<thumbprint>\Blob` | Operator CA install location (inferential) | Inferential |
| Operator string | `Z:/Builder/out/g4myb34r_backdoor.go` | Embedded source path (DWARF compile-unit) | binary |
| Operator string | `C:/Users/fuckthereversers/go/pkg/mod` | Embedded operator Go module cache path (DWARF) | binary |
| Build ID prefix | `pXjhKBRwl8Jz266eHpWV` | Go BuildID for the analyzed sample (per-build artifact) | binary |
| Go compiler | `go1.21.0` (August 2023) | Toolchain version embedded in binary | binary |

### Beacon shape indicators (binary)

The following shape patterns appear in every GAMYBEAR beacon and are useful for network-content matching independent of file hashes or IPs:

```
Registration POST body:
  {"uuid":"<UUIDv4>","hostname":"<base64>","ip_address":"<base64-or-empty>"}

Command poll GET response body:
  {"Command":"<string>","Arguments":"<string>"}

Result POST body:
  {"uuid":"<UUIDv4>","command":"<echoed-cmd>","output":"<base64-of-stdout>"}

Persistence file:
  {"update_server":"<URL>","uuid":"<UUIDv4>","hostname":"<base64>","ip":"<base64-or-empty>"}
```

Two stable beacon-shape artifacts worth flagging:

- Every hostname field decodes to a value ending in `\r\n` (whoami output trailing CRLF). In base64, every observed hostname value therefore ends in `DQo=`.
- Every ip_address field from a Windows 11 22H2+ host is the empty string `""` (wmic absence on modern Windows).

---

## Hunting guidance

Queries below target the binary's behavior and the kill chain's documented stages. Threshold values are starting points and should be tuned to environment.

### Sigma — GAMYBEAR persistence file creation

```yaml
title: GAMYBEAR identity file creation
id: 1a4f8c2b-3e7d-4f9a-b8d2-c6e9f3a4b1c8
status: experimental
description: Detects creation of the GAMYBEAR identity file at %APPDATA%\updater.json by any process
references:
  - https://cert.gov.ua/article/6286219
  - https://github.com/yankywilson/gamybear
author: Yanky Wilson
date: 2026/05/27
tags:
  - attack.persistence
  - attack.t1547
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '\Roaming\updater.json'
  condition: selection
falsepositives:
  - Legitimate software using identical path is unlikely; review process Image and parent context
level: high
```

### Sigma — Non-system PowerShell installing root certificate

```yaml
title: Non-administrative PowerShell installing root certificate
id: 2b5g9d3c-4f8e-5g0b-c9e3-d7f0a4b5c2d9
status: experimental
description: |
  Detects PowerShell writing a certificate to the system root trust store.
  This is the upstream UAC-0241 kill-chain step required for GAMYBEAR to function.
  Legitimate enterprise software rarely performs this from non-elevated PowerShell.
references:
  - https://github.com/yankywilson/gamybear
author: Yanky Wilson
date: 2026/05/27
tags:
  - attack.defense_evasion
  - attack.t1553.004
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    Image|endswith: '\powershell.exe'
    TargetObject|contains:
      - 'HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\'
      - 'HKCU\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\'
    EventType: SetValue
  filter_system:
    IntegrityLevel:
      - System
  condition: selection and not filter_system
falsepositives:
  - Legitimate IT certificate deployment from non-elevated contexts (rare; should be allowlisted)
level: high
```

### Sigma — Sustained TLS bad_certificate alerts (Go default JA3)

```yaml
title: Sustained TLS validation failures from Go default crypto/tls client
id: 3c6h0e4d-5g9f-6h1c-d0f4-e8g1b5c6d3e0
status: experimental
description: |
  Detects sustained TLS bad_certificate alerts from a host using Go's default
  crypto/tls Client Hello fingerprint. Catches GAMYBEAR and any other Go binary
  making strict-validation TLS to a self-signed or untrusted endpoint.
references:
  - https://github.com/yankywilson/gamybear
author: Yanky Wilson
date: 2026/05/27
tags:
  - attack.command_and_control
  - attack.t1071.001
logsource:
  product: zeek
  service: ssl
detection:
  selection:
    ja3: '397c55c9aaf9820f7655666ee7fc3c2d'
    validation_status: 'self signed certificate'
  condition: selection | count() by src_ip > 5
  timeframe: 5m
falsepositives:
  - Misconfigured internal mTLS endpoints accessed by Go-based monitoring agents
level: medium
```

### KQL (Microsoft Defender / Sentinel) — Updater.json creation

```kql
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath endswith @"\Roaming\updater.json"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, 
          FolderPath, SHA256, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

### KQL — Non-system PowerShell writing to root cert store

```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "powershell.exe"
| where RegistryKey has_any (
    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates",
    @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates"
  )
| where InitiatingProcessIntegrityLevel != "System"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RegistryKey,
          RegistryValueName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

### Splunk SPL — GAMYBEAR C2 URL pattern in proxy/DNS/firewall logs

```spl
index=proxy OR index=zeek_http
| eval url_match = if(match(url, "/c2/get_commands/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), 1, 0)
| eval url_match2 = if(match(url, "/c2/command_out/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), 1, 0)
| eval url_match3 = if(match(url, "/register$"), 1, 0)
| where url_match=1 OR url_match2=1 OR url_match3=1
| stats count by src_ip, dest_ip, dest_host, url, user_agent
| sort -count
```

### Splunk SPL — Go-default User-Agent to non-allowlisted destination

```spl
index=proxy OR index=zeek_http
| where useragent="Go-http-client/1.1"
| stats count by src_ip, dest_ip, dest_host
| where count > 50
| lookup allowlisted_go_destinations dest_host OUTPUT allowlisted
| where isnull(allowlisted) OR allowlisted="false"
| sort -count
```

### Hunt hypotheses

For analysts using a hypothesis-driven hunt workflow, the following hypotheses correspond to phases of the GAMYBEAR kill chain that are observable in defender telemetry:

1. **Hypothesis H1:** *A GAMYBEAR instance is running in our environment but failing TLS validation because the operator's CA was not installed on this host.* Evidence: sustained Go-default JA3 + bad_certificate alerts at 5-second cadence from any host to any destination not on the allowlist. Investigation: capture full PCAP from suspect host, identify Go binary executing, recover hash and source.

2. **Hypothesis H2:** *A GAMYBEAR instance is running successfully because the operator's CA was installed on this host.* Evidence: presence of `%APPDATA%\updater.json` on host AND a non-Microsoft-issued root certificate in `HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\`. Investigation: extract the rogue cert, identify the issuing operator, recover Go binary, recover PowerShell stage from execution history.

3. **Hypothesis H3:** *An earlier-stage UAC-0241 kill chain (LNK → mshta → JS → PS) ran but the GAMYBEAR drop failed.* Evidence: process tree of `explorer.exe → mshta.exe → script execution → powershell.exe` within recent history, no resulting Go binary executing. Investigation: recover mshta arguments, recover JS and PS stages from script-block logging, identify next stage.

4. **Hypothesis H4:** *A second variant or build is deployed in our environment.* Evidence: file artifact `updater.json` with a `update_server` value other than `https://185[.]223[.]93[.]102`. Investigation: this is the variant-tracking lead. Recover the new C2, recover the new binary, perform delta analysis against the analyzed sample.

---

## Detection content links

Detection content for this family is published openly in my repository:

- **YARA rules:** [yara/](https://github.com/yankywilson/gamybear/tree/main/yara) (11 rules across three files, covering operator-attributable strings, runtime metadata and struct shape signatures)
- **Suricata rules:** [suricata/gamybear.rules](https://github.com/yankywilson/gamybear/blob/main/suricata/gamybear.rules) (10 rules covering known C2, beacon shapes, JA3-plus-alert, persistence file path in traffic)
- **Snort rules:** [snort/gamybear.rules](https://github.com/yankywilson/gamybear/blob/main/snort/gamybear.rules) (7 rules covering equivalent patterns in Snort 2.x/3.x syntax)
- **STIX 2.1 bundle:** [ioc/stix2-bundle.json](https://github.com/yankywilson/gamybear/blob/main/ioc/stix2-bundle.json) (machine-readable IOC distribution suitable for ingest into TIPs supporting STIX 2.1)
- **IOC CSV:** [ioc/iocs.csv](https://github.com/yankywilson/gamybear/blob/main/ioc/iocs.csv) (machine-readable indicator list with type, value, source, confidence)
- **Reconstructed Go source:** [analysis/reconstructed_source.go](https://github.com/yankywilson/gamybear/blob/main/analysis/reconstructed_source.go) (high-fidelity reconstruction of the operator's source code from Ghidra decompilation plus DWARF debug info)

All content is published under MIT license. Attribution appreciated, not required.

---

## Variant tracking guidance

The most valuable single follow-up artifact is the unanalyzed `ieupdater.exe` variant (SHA-256 `5d3f5d174369b34c436df0ad467236bd477b12b817768e19113969e08d74ef5d`). Variant comparison between the analyzed `svshosts.exe` and the unanalyzed `ieupdater.exe` would yield:

- Build cadence indicators (BuildID delta, Go compiler version delta)
- Source-code evolution evidence (function additions, function removals, struct field changes)
- Operator OPSEC evolution evidence (DWARF stripped or retained, persona strings present or removed)
- TLS implementation evolution (is `http.DefaultClient` still used, or has the operator switched to a custom `tls.Config`?)

The TLS implementation question is the highest-value follow-up. If `ieupdater.exe` still uses `http.DefaultClient`, the operator has not noticed the bug and the network detection content in this brief continues working on the new variant. If `ieupdater.exe` uses `tls.Config{InsecureSkipVerify: true}` or cert pinning, the operator has noticed and the network detection content stops working. Either outcome is useful intelligence.

For analysts tracking future builds beyond these two known variants, the indicators to watch for in any candidate GAMYBEAR sample are:

| Variant indicator | Significance |
| --- | --- |
| Go version differs from go1.21.0 | Toolchain refresh; team is actively building |
| DWARF debug sections stripped | OPSEC improvement; team learned |
| BuildID changed | Confirms a different build (expected for any new sample) |
| C2 IP differs from 185[.]223[.]93[.]102 | Infrastructure rotated; possible new pivot opportunity |
| `tls.Config` with `InsecureSkipVerify: true` | TLS fix via the lazy path; bot functional in clean envs |
| Cert pinning via `VerifyPeerCertificate` callback | TLS fix via the proper path; bot functional in clean envs |
| Multiple C2 IPs in a `[]string` slice | Resilience improvement |
| Domain-based C2 with valid Let's Encrypt cert | Major OPSEC improvement; bot functional everywhere |
| Anti-VM or anti-debug checks added | Anti-analysis tradecraft introduced |
| String obfuscation or runtime decoding | Anti-analysis tradecraft introduced |
| `context.WithCancel` for goroutine shutdown | Code-quality improvement; team is learning Go properly |
| Real shell support (`cmd.exe /c` wrapping) | Capability expansion |
| Sleep jitter (randomized intervals) | Beaconing OPSEC improvement |
| Argument parser handling quoted strings | Code-quality improvement |

A future variant exhibiting any of these changes signals operator iteration. A future variant exhibiting none confirms the team continues to ship developmentally immature tooling and that the defensive content in this brief continues to work.

The CFG-style configuration structure observed in similar Go-language families (e.g. the DonutCluster loader I previously documented) is not present in GAMYBEAR — its configuration is hardcoded via Go string literals in `.rdata`. If a future variant adopts a CFG-style structure, that would be a substantial code-base evolution and worth flagging.

---

## Intelligence gaps

Documenting the gaps explicitly. These are the questions whose answers would improve confidence in the assessments above.

| Gap | Why it matters | How to close |
| --- | --- | --- |
| `ieupdater.exe` variant analysis | Variant comparison reveals operator iteration cadence; tells us whether the TLS flaw has been fixed | Pull sample from CERT-UA contacts, VirusTotal Intelligence Enterprise, or private vendor feeds; perform full RE |
| `updater.ps1` PowerShell stage analysis | Direct verification of the CA-install inference; reveals the upstream stage's other operations | Acquire PS1 sample via CERT-UA IOC hash; perform full PowerShell deobfuscation and analysis |
| UAC-0241 ↔ Gamaredon relationship | Determines whether this is a sub-cluster, a parallel team, or coincidental targeting overlap | Long-form open-source research; coordination with CERT-UA; cross-correlation of infrastructure pivots |
| C2 server response payloads | Both /register and /c2/command_out/ responses are decoded but unused by the bot; what does the C2 actually return? | Unresolvable from bot binary; would require operator-side access or coordinated C2 takeover |
| Operator command repertoire | What commands the operator actually executes in operations vs. what the bot is theoretically capable of | Unresolvable from binary; would require victim telemetry or C2 logs |
| Operator team size, identity, location | Beyond the `fuckthereversers` persona, no identifying information available | Open-source persona pivots (GitHub, grep.app, Sourcegraph, Russian-language forums); legal-process channels if applicable |
| Build cadence and release frequency | BuildIDs differ per build; correlating BuildIDs across multiple acquired samples reveals release cadence | Requires multiple variant samples |
| Lateral movement and impact within victim environments | What the operator does post-implant beyond credential dumping and SOCKS proxying | Requires victim-side telemetry, IR engagement notes from compromised orgs |
| Validin / DomainTools passive DNS history on C2 IP and grizzlyconnect[.]net | Infrastructure context, related hosts, historical resolution patterns | Pivot through commercial passive DNS providers (not performed in this work) |
| ThreatFox / URLhaus enrichment on related IPs | Additional malware family associations on shared infrastructure | Routine abuse.ch lookups (not performed in this work) |

---

## Recommendations

### For SOC teams

- **Deploy now:** Sigma rules from this brief (GAMYBEAR persistence file creation, non-system PowerShell cert install, sustained Go-default JA3 + bad_certificate alerts). All three are high-confidence and low false-positive in typical enterprise environments.
- **Audit retroactively:** Search 30-day historical telemetry for any prior TLS bad_certificate alert volume from Go-default JA3 fingerprints. Sustained patterns from past months may indicate prior GAMYBEAR exposure that failed silently.
- **Audit retroactively:** Search 30-day historical telemetry for non-system PowerShell writes to the root cert store. Any hit warrants forensic investigation regardless of UAC-0241 attribution.
- **Tune thresholds:** The TLS-failure detection requires careful threshold tuning to suppress noise from legitimate misconfigured mTLS endpoints. Start with five or more bad_certificate alerts per source host per 60 seconds, sustained across three consecutive minutes. Tune based on environment baseline.
- **Document the kill chain:** The full UAC-0241 chain (LNK → mshta → JS → PS → Go binary) is well-documented and worth modeling in your detection-coverage matrix. Multi-stage chains where each stage produces detectable telemetry are easier to catch than single-stage drops.

### For CTI teams

- **Add UAC-0241 to active tracking** if not already present in your watch list. The intrusion set is publicly documented (CERT-UA) but undercovered by Western commercial vendors as of analysis date.
- **Subscribe to CERT-UA advisories** if not already a subscriber. Recent CERT-UA output has been disproportionately useful for early visibility into Russian-aligned tooling.
- **Watch for variant indicators** per the variant tracking guidance above. A second sample of GAMYBEAR with materially different code is a meaningful intelligence event.
- **Track the Gamaredon adjacency.** If UAC-0241 turns out to be a Gamaredon sub-cluster, the cross-reference materially expands what we know about Gamaredon's current operational tooling. If they turn out to be unrelated, that itself is a finding.

### For IR teams

- **If GAMYBEAR is found on an endpoint during IR**, prioritize three artifacts for collection beyond standard forensic acquisition: (1) the full Go binary itself, (2) the upstream `updater.ps1` PowerShell stage from execution history or disk artifacts, (3) the Windows certificate store enumeration showing any non-system root certs installed by the operator.
- **Scope assessment** for the engagement should include enumerating `%APPDATA%\updater.json` across all endpoints in the environment. This file's presence is a high-confidence indicator of GAMYBEAR execution and is faster to scan for than file hashes (which rotate per build) or YARA matches (which require process memory scanning).
- **Trust store hygiene** is worth checking as part of post-IR remediation regardless of GAMYBEAR specifically. Enumerate `HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\` and verify no non-system, non-allowlisted root certificates are present. The Windows command `certutil -store -enterprise Root` lists enterprise-deployed roots; anything outside that and the Microsoft Root Certificate Program warrants investigation.
- **Lateral movement assumption:** If GAMYBEAR is observed, assume the operator has also deployed RESOCKS and used LaZagne to extract credentials. The operator's documented tooling supports credential-driven lateral movement; assume credentials in the compromised user's cache are exposed and rotate accordingly.

---

## Source reliability and methodology

All findings labeled **(binary)** derive from my own reverse engineering of GAMYBEAR sample `f4cfbd86609b558a76e43a8da7a47b211d4c498d1167b65bf43aa199e4a252fd` using Ghidra with the GolangAnalyzerExtension plugin, GoReSym for build-metadata extraction, FakeNet-NG for dynamic network simulation, and FLARE-VM Windows 11 (build 10.0.26200) as the detonation environment. Static analysis covered all 13 user-defined `main.*` functions with verification against assembly and against DWARF debug information retained in the binary. Dynamic detonation ran for 60+ minutes with full network capture.

All findings labeled **(CERT-UA)** derive from CERT-UA Article 6286219 (CERT-UA#18329), published 2025-11-18. CERT-UA is a national CSIRT with direct access to incident response engagements at victim organizations and is the primary source for UAC-0241 cluster-level intelligence. CERT-UA's reporting accuracy in the post-2022 period has been consistently high.

Findings labeled **(inferential)** are explicitly flagged where they appear. These are conclusions logically required by observed facts but not directly verified through additional evidence collection. They should be treated as high-priority follow-up targets rather than established facts.

This brief reflects analysis state as of 2026-05-26. Network indicators may rotate; file hashes will rotate per build; the C2 IP `185[.]223[.]93[.]102` was confirmed reachable at the TCP layer during the analysis window but live operational status may change.

---

**Companion documents:**

- [GAMYBEAR reverse engineering writeup](https://yankywilson.github.io/2026/05/26/gamybear-uac-0241-investigation/) — the narrative version of how the analysis unfolded
- [yankywilson/gamybear](https://github.com/yankywilson/gamybear) — the full repository with reconstructed source, detection content and IOCs in machine-readable formats

If you build on this work, please open an issue with additional indicators or corrections. Operator iteration is ongoing and the assessments in this brief have a finite shelf life.
