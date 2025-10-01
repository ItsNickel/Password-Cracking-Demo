# Password-Cracking-Demo
Im currently learning about password cracking and I thought it would be fun to made a reproducible demo that shows how common password-hash attacks work (wordlist / mask / hybrid / rules) and—just as importantly—how to defend against them.

# What this repo contains

generate_hashes.py — makes a tiny set of test plaintexts and outputs example hashes (MD5, NTLM, bcrypt) into hashes/.
run_demo.sh — safe wrapper that runs reproducible, low-cost Hashcat / John commands against a mini wordlist and writes results to results/.
sample_wordlists/mini-rockyou.txt — intentionally tiny (10–100 entries) for CI-friendly runs.
hashes/ — demo hash files (small, test-only).
results/cracked.csv — sample output showing what was cracked and how.
docs/ — short writeups: attack-experiments.md (what commands were run, times, notes) and defenses.md (salting, bcrypt/argon2, MFA, rate limits).
README.md, LICENSE, .gitignore.

# Quick start (Linux / WSL / Kali)

Clone the repo:
git clone https://github.com/<you>/password-cracking-demo.git
cd password-cracking-demo

Install tools:
sudo apt update
sudo apt install -y hashcat john python3 python3-pip
pip3 install bcrypt pycryptodome pandas 

Generate demo hashes (small, basic set):
python3 generate_hashes.py
# outputs into ./hashes/

Run the demo (uses the mini wordlist so its fast and safe):
chmod +x run_demo.sh
./run_demo.sh
# results written to ./results/cracked.csv

# Example commands (documented in the repo)

Hashcat (MD5, straight wordlist):
hashcat -m 0 -a 0 hashes/hashes_md5.txt sample_wordlists/mini-rockyou.txt --potfile-path=potfile --show

Hashcat mask (known pattern: 6 letters + 2 digits):
hashcat -m 0 -a 3 hashes/hashes_md5.txt '?l?l?l?l?l?l?d?d'

Hybrid (wordlist + 2 digits):
hashcat -m 0 -a 6 hashes/hashes_md5.txt sample_wordlists/mini-rockyou.txt '?d?d'

John the Ripper (wordlist + rules):
john --wordlist=sample_wordlists/mini-rockyou.txt --rules --format=raw-md5 hashes/hashes_md5.txt
