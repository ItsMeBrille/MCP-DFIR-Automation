#!/usr/bin/env python3
"""Try candidate keys against the /api/data channel."""
from base64 import b64decode
from Crypto.Cipher import AES

# A short keylog event - 44 bytes b64 (16-byte ciphertext after 1-byte type tag)
SAMPLE = "Aft8mr3RJ6zjFR66w+mTbjPVEvZzp4/vdYDYr99GtQFK"  # 44B heartbeat that repeats
SAMPLE2 = "ARoJrzWVL26gH6JkZPvbjR8f/JXr+BEV2DYhNDI5mC2ACh9fiSNXkLE2Rm8DeVkwhrtIUmwjESAsDafhn1qhgzeX9XL12LW9ZEFnxNOtGUEp"

def try_key(key, label, sample=SAMPLE):
    raw = b64decode(sample)
    ct = raw[1:]
    try:
        pt = AES.new(key.ljust(16, b"\x00")[:16], AES.MODE_ECB).decrypt(ct)
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in pt)
        score = printable / len(pt)
        if score > 0.5:
            print(f"  ** {label!r:40s} -> {pt!r}")
        return score, pt
    except Exception as e:
        return 0, None

candidates = [
    b"ANDERS-DESKTOP",
    b"anders-desktop",
    b"Anders-Desktop",
    b"ANDERS-DESKTOP\n",
    b"Host: ANDERS-DES",
    b"Host: ANDERS-DESKTOP",
    b"ANDERS-DESKTOPan",   # if it kept reading past
    b"ANDERS-DESKTOP\nUser: anders\n"[:16],
    b"DESKTOP-ANDERS",
    b"updater.exe",
    b"MicrosoftUpdater",
    b"Mozilla/5.0",
    b"MiccosoftUpdate.",
    b"MiccosoftUpdate",
    b"miccosoftupdate.",
    b"windowsupdater.t",
    b"\x00" * 16,
    b"0123456789ABCDEF",
    b"AAAAAAAAAAAAAAAA",
]

print(f"=== Trying SAMPLE = {SAMPLE} (44B repeating heartbeat) ===")
for k in candidates:
    try_key(k, k.decode("latin1", "replace"))

print(f"\n=== Trying SAMPLE2 = first 108B exfil ===")
for k in candidates:
    try_key(k, k.decode("latin1", "replace"), SAMPLE2)

# Maybe key derivation includes \n: extract via sscanf %255s - strict whitespace stop
# Maybe the implant builds a separate host with format "Host: %s\r\n" => "Host: ANDERS-DESKTOP\r\n"
# Try that:
for k in [
    b"Host: ANDERS-DE",
    b"Host: ANDERS-DES",
    b"Host: ANDERS-DESKTOP\r\n"[:16],
    b"Host: ANDERS-DESKTOP"[:16],
    b" ANDERS-DESKTOP",
    b"ANDERS-DESKTOP" + b"\x00\x00",
]:
    try_key(k, k)

# Try every 16-byte sliding window over the recon string
recon = b"Host: ANDERS-DESKTOP\nUser: anders\nArch: x64\nCPUs: 4\nRAM: 8185 MB\n"
print("\n=== sliding window over recon string ===")
for i in range(len(recon) - 15):
    k = recon[i:i+16]
    try_key(k, f"recon[{i}:{i+16}]={k!r}")
