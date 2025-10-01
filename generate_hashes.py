#!/usr/bin/env python3
"""
generate_hashes.py
Creates a tiny, safe set of demo passwords and outputs:
 - ./hashes/hashes_md5.txt
 - ./hashes/hashes_ntlm.txt
 - ./hashes/hashes_bcrypt.txt
 - ./results/cracked.csv (empty template)
Also writes a tiny sample wordlist at ./sample_wordlists/mini-rockyou.txt

ONLY for educational/demo purposes. Do NOT use real passwords or upload real dumps.
"""
import os
import hashlib
import csv
import sys

try:
    import bcrypt
except ImportError:
    print("bcrypt not installed. Install with: pip3 install bcrypt")
    bcrypt = None

# demo plaintexts (small, safe)
PASSWORDS = [
    "password123",
    "letmein",
    "ilovepie",
    "sunshine7",
    "qwerty",
    "NikhilsDog01"  # example test password — do not use for real accounts
]

BASE = os.path.dirname(__file__) or "."
HASH_DIR = os.path.join(BASE, "hashes")
SAMPLE_DIR = os.path.join(BASE, "sample_wordlists")
RESULTS_DIR = os.path.join(BASE, "results")

os.makedirs(HASH_DIR, exist_ok=True)
os.makedirs(SAMPLE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# write small sample wordlist (like a mini rockyou)
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

# helpers
def ntlm_hash(plaintext: str) -> str:
    # NTLM is MD4 over UTF-16LE
    h = hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
    return h

def md5_hash(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode()).hexdigest()

def bcrypt_hash(plaintext: str, rounds: int = 4) -> str:
    # Use a low cost (4) for demo reproducibility. Document this in README.
    if bcrypt is None:
        return "<bcrypt-not-generated>"
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(plaintext.encode(), salt).decode()

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
        ntlm_h = ntlm_hash(pw)
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
