#!/usr/bin/env python3
"""Decrypt C2 traffic from updater.exe.

Cipher: AES-128-ECB with PKCS#7 padding.
Key: first 16 bytes of host string from /api/info recon (zero-padded).
Exfil bodies: 1-byte type tag prepended before encrypt+base64.
Command field (server -> client): just AES+base64 (no type tag).
"""
from base64 import b64decode

try:
    from Crypto.Cipher import AES  # pycryptodome
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    class AES:  # tiny shim
        MODE_ECB = 1
        @staticmethod
        def new(key, mode):
            class _C:
                def __init__(s, k):
                    s.k = k
                def decrypt(s, ct):
                    c = Cipher(algorithms.AES(s.k), modes.ECB()).decryptor()
                    return c.update(ct) + c.finalize()
            return _C(key)


def unpad(pt: bytes) -> bytes:
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p]) * p:
        return pt[:-p]
    return pt


def aes_dec(key: bytes, b64: str) -> bytes:
    ct = b64decode(b64)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    return unpad(pt)


KEY_ANDERS = b"ANDERS-DESKTOP".ljust(16, b"\x00")

COMMANDS = [
    ("17:48:20.010", "Q52aB5TFVA5uEM/IeZ0Kyg=="),
    ("17:49:20.346", "ISL6QPPTKg2tMQgQfCRu10uFvjw0koh/MudkA/oUS98="),
    ("17:50:50.567", "ISL6QPPTKg2tMQgQfCRu134S+r4B5p6X4HZo/X4d/vs="),
    ("17:51:50.695", "A45yK3lKmkrMpH01AxtchDAHsYTB95vlGUdgdYR6EekutR6WwKdtMbvDbfUfwsKt"),
]

print("=== Decrypted C2 commands (windowsupdater.tk/windows/checkforupdate response) ===")
for ts, c in COMMANDS:
    try:
        print(f"{ts}  {aes_dec(KEY_ANDERS, c)!r}")
    except Exception as e:
        print(f"{ts}  ERROR: {e}")

EXFIL_1944 = (
    "A7it1Mht0/eBAGAKD7BCx1pdNGKSC7LgWUfhDHU9IVnR2nytjgZZKKLAaqLLhOwLqTCg"
    "06/uVhU7nsMPdEz3vnpenGS56yua1aRlW5w2kSTsY+ik6z1Zwuxv6x0bYGXlfmkQQVqf"
    "olRqtjZF8r/VyaN62xSp1+d3blUZuKIwGq2RHEIExwnh2IBtc/6NB4SJFg2MGngv8l56"
    "r2qfzuZ9dNP0rfv+SNJD53nBTEs7lQcEHuVlkczLk3GrpZZce3A7Yq+eHaQyX/DGBNSg"
    "7QVLf9gXc9pSUGXONFhbS8r5HANe5tUHENCPGJ5DV7PsPQUv9fszZERiweljc9iHwNuE"
    "plk59LONW4T7aXAtf3o8Qk0w8KY0wPDL3MQJQ0FGgoyfn78hHWbeHY8BxqvHadv6Zhk2"
    "q2aPw8koQcKAVn2lh5dU/dDlYQjSH9dAAjmIB2+DqrJmTQS8oCT7t7YGNEU3tDJgRPCT"
    "KPFy/Nd0DbGRhiBMQ1ZuR65eTEjuRxKr3YVaW8RAVCsLa2bmVf3AyihsNZj+S25wp4qG"
    "hENRfMJB41DIZGHzl4KqWznMD4RDKxMe6hXrbYUUCTq6GCPGOvqNauj9gAXTi4xy6C5S"
    "b63Lcpre+CwQ0x4nLGlMbKvM0HVfgN9dB0mfJW0by+S5tKv5gJ6fg1rmzK/agDyYBtuX"
    "PFhjnFmokwyI5XYD3WB5HMiM5ne4Lh2E1QVJtaFuFzYqv/Zhcv+hZ0xPbWhs540G9Myk"
    "4iApX1MhnB87VGQsmPU8XbaaQywjuT5XNUxYgLNFcWK8IRbYPhK5k1URECwF9M//nfRI"
    "HVoCnO5PIINcou8V22KtMm3JTBjMg8Js0kB28ptLew/+503K9QVxfEU1MH1TA/nO2Yt1"
    "IAWqjdkJSwWrySwftl4kw+W+F79oNdLzTD4ZIVu65tXGARhl+TRVQ6VRXSXUvC4kleBe"
    "0YhXBe85z7NkKggoSurVDGkGp9QSYB1vbEzHhQIAtZ4ENWTHEm2UphJDr58XTJUBTM2x"
    "g5SKX+kEgJuc6ijWsrxEzNHhfSU2kVeSk0+0jkrkVNNYVsAfDRduWgWyTAdxIOthPAYf"
    "EsctO3fsfvnZQ7tNoIpIPIzFpII2KLqRKpTtVKkMuaHNpYfrjxcr1ITQ45XEdXxPJ8dL"
    "dV9bmncnfo7BdhpqJrSad6JKefdwIYJWLaL5hvuhnnsQg6acqqUOPiUGBa9qqS1ZJ1bb"
    "YeFKiDQkRJHjeom1ylixMoqcb5KoteuxnLOk2EcDuaM7NSQoswizBqAEkV7NoawnlRJ9"
    "0lxnWNv3Sn0dvF44gZqHqpPvlXFBKuPBr+wLc3nKVvR1EbvsJ+2DMjNOrq+J/3mAsmme"
    "X/d/RNsGrNfAvOPgu7L4EzWl8FL2a3mH0qxI8C7SHKSr8s+1Pmz1MN46oMFnBfuDx+mf"
    "3dwskIKkeYxLH0wDdEuSHBMJLL7CKkAMDvtyjz7zIiiOC8zJQqmfJHne3agRU2cCmKP1"
    "WmtTzo6T08OHoHH5U46YgKIm2Xv4aNAmw/IF+/AK5HT485soS6b+4jiap0LUXEdMy55i"
    "awXsROuiVhB6GofOtzdwZJGMmLFBOPDI7hXtrybK2Q550MPa3gbfoTF1twd5gT3Lcn/e"
    "mCI5H7+uAwZnUUQcUc4mhkhUskfy61KZSMqFURUUggCGrAevZV5GLupJ0uOwadfXyqq1"
    "0lY63OJcEE94kg+SOvuxufrK/Qwrk3HJwyjdyyj2RLPiahQQSR4GcXIqU1lfcispcRyn"
    "I3acMbYH7vaXXcqQjW/yIsmOOZRajzKgjw0rJSJOvUqqo51gqk+XgrGXUjQdpqiZQx7Q"
    "bkFNGjLR3lIfhD+Z5K123XOSNn4ZNq+hjK+CULTFuN3zLAZ4jFQQIPRAToSjU6HKmjF8"
    "wWDnKuk1t0L1EYQarjLzBuvZdQ7D3ZXpVvTysco="
)

print("\n=== Decrypted 1944-byte exfil POST (windowsupdater.tk/update/servicedata @17:51:51) ===")
raw = b64decode(EXFIL_1944)
# layout: [1-byte type tag][AES-ECB ciphertext]
type_tag = raw[0]
ct = raw[1:]
print(f"type-tag byte = 0x{type_tag:02x}  (3 = command output), ct len = {len(ct)}")
pt = AES.new(KEY_ANDERS, AES.MODE_ECB).decrypt(ct)
body = unpad(pt)
print(f"plaintext length = {len(body)} bytes\n")
try:
    print(body.decode("utf-8", errors="replace"))
except Exception as e:
    print(repr(body))

# save to file
with open("polen.eml.recovered", "wb") as f:
    f.write(body)
print("\n[+] Wrote polen.eml.recovered")
