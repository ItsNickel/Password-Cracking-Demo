#!/usr/bin/env python3
"""
generate_hashes.py (fixed)
Creates a tiny, safe set of demo passwords and outputs:
 - ./hashes/hashes_md5.txt
 - ./hashes/hashes_ntlm.txt
 - ./hashes/hashes_bcrypt.txt
 - ./results/hash_map.csv
Also writes a tiny sample wordlist at ./sample_wordlists/mini-rockyou.txt

This version uses Crypto.Hash.MD4 if available, otherwise a pure-Python MD4 fallback.
ONLY for educational/demo purposes. Do NOT use real passwords or upload real dumps.
"""
import os
import hashlib
import csv
import sys

# Try to import bcrypt (optional)
try:
    import bcrypt
except Exception:
    bcrypt = None

# Try to use pycryptodome's MD4; otherwise provide a pure-Python MD4 implementation
USE_CRYPTO_MD4 = False
try:
    from Crypto.Hash import MD4 as CryptoMD4  # pycryptodome
    USE_CRYPTO_MD4 = True
except Exception:
    USE_CRYPTO_MD4 = False

# Pure-Python MD4 fallback (small, public-domain style implementation)
# Adapted for clarity; correct for NTLM usage (MD4 over UTF-16LE)
def md4_fallback(data: bytes) -> bytes:
    # Implementation based on RFC 1320 algorithmic steps
    # This is a compact implementation — uses 32-bit arithmetic
    import struct

    # Functions for rounds
    def F(x, y, z): return ((x & y) | (~x & z)) & 0xFFFFFFFF
    def G(x, y, z): return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF
    def H(x, y, z): return (x ^ y ^ z) & 0xFFFFFFFF
    def lrot(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    # Pre-processing (padding)
    msg = data
    orig_len_bits = (8 * len(msg)) & 0xffffffffffffffff
    msg += b'\x80'
    while (len(msg) % 64) != 56:
        msg += b'\x00'
    msg += struct.pack('<Q', orig_len_bits)

    # Initialize MD buffer
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    # Process in 16-word blocks
    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i+64]))
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        s = [3,7,11,19]
        for j in range(16):
            k = j
            r = s[j % 4]
            A = lrot((A + F(B, C, D) + X[k]) & 0xFFFFFFFF, r)
            A, B, C, D = D, A, B, C

        # Round 2
        s = [3,5,9,13]
        for j in range(16):
            k = (j % 4) * 4 + (j // 4)
            r = s[j % 4]
            A = lrot((A + G(B, C, D) + X[k] + 0x5a827999) & 0xFFFFFFFF, r)
            A, B, C, D = D, A, B, C

        # Round 3
        s = [3,9,11,15]
        order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for j in range(16):
            k = order[j]
            r = s[j % 4]
            A = lrot((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xFFFFFFFF, r)
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D)

def ntlm_hash_with_md4(plaintext: str) -> str:
    """
    NTLM = MD4(UTF-16LE(plaintext)), hex-encoded (lowercase)
    Uses pycryptodome if available, otherwise fallback.
    """
    data = plaintext.encode('utf-16le')
    if USE_CRYPTO_MD4:
        h = CryptoMD4.new()
        h.update(data)
        return h.hexdigest()
    else:
        return md4_fallback(data).hex()

# Other hash helpers
def md5_hash(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode()).hexdigest()

def bcrypt_hash(plaintext: str, rounds: int = 4) -> str:
    # Use a low cost (4) for demo reproducibility. Document this in README.
    if bcrypt is None:
        return "<bcrypt-not-generated>"
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(plaintext.encode(), salt).decode()

# demo plaintexts (small, safe)
PASSWORDS = [
    "password123",
    "letmein",
    "ilovepie",
    "sunshine7",
    "qwerty",
    "NikhilsDog01"
]

BASE = os.path.dirname(__file__) or "."
HASH_DIR = os.path.join(BASE, "hashes")
SAMPLE_DIR = os.path.join(BASE, "sample_wordlists")
RESULTS_DIR = os.path.join(BASE, "results")

os.makedirs(HASH_DIR, exist_ok=True)
os.makedirs(SAMPLE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# write small sample wordlist (mini-rockyou)
mini_path = os.path.join(SAMPLE_DIR, "mini-rockyou.txt")
with open(mini_path, "w") as f:
    f.write("\n".join([
        "password",
        "password123",
        "123456",
        "qwerty",
        "letmein",
        "ilovepie",
        "sunshine7",
        "welcome1",
        "admin",
        "NikhilsDog01"
    ]) + "\n")
print(f"Wrote tiny sample wordlist -> {mini_path}")

# write hashes files and a CSV map
md5_path = os.path.join(HASH_DIR, "hashes_md5.txt")
ntlm_path = os.path.join(HASH_DIR, "hashes_ntlm.txt")
bcrypt_path = os.path.join(HASH_DIR, "hashes_bcrypt.txt")
csv_map_path = os.path.join(RESULTS_DIR, "hash_map.csv")

with open(md5_path, "w") as f_md5, \
     open(ntlm_path, "w") as f_ntlm, \
     open(bcrypt_path, "w") as f_bcrypt, \
     open(csv_map_path, "w", newline="") as f_csv:

    csv_writer = csv.writer(f_csv)
    csv_writer.writerow(["hash_type", "hash", "plaintext", "note"])

    for pw in PASSWORDS:
        md5_h = md5_hash(pw)
        ntlm_h = ntlm_hash_with_md4(pw)
        bcrypt_h = bcrypt_hash(pw)

        f_md5.write(md5_h + "\n")
        f_ntlm.write(ntlm_h + "\n")
        f_bcrypt.write(bcrypt_h + "\n")

        csv_writer.writerow(["MD5", md5_h, pw, "demo"])
        csv_writer.writerow(["NTLM", ntlm_h, pw, "demo"])
        csv_writer.writerow(["BCRYPT", bcrypt_h, pw, "demo (low cost)"])

print(f"Wrote demo hashes -> {md5_path}, {ntlm_path}, {bcrypt_path}")
print(f"Wrote mapping CSV -> {csv_map_path}")

# create empty results template for cracking outputs (safe)
cracked_csv = os.path.join(RESULTS_DIR, "cracked.csv")
with open(cracked_csv, "w", newline="") as rcsv:
    w = csv.writer(rcsv)
    w.writerow(["hash_type", "hash", "plaintext", "attack_type", "time_s", "notes"])
print(f"Wrote empty results template -> {cracked_csv}")

print("\nGeneration complete. Reminder: use only the mini wordlist for CI/demo runs.")
