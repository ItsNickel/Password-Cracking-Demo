#!/usr/bin/env bash
# run_demo.sh
# Safe demo runner — uses the tiny sample_wordlists/mini-rockyou.txt only.
# It checks for hashcat and john (if present) and runs small, reproducible commands.
# Do NOT point this at large wordlists or real dumps.

set -euo pipefail

BASE="$(cd "$(dirname "$0")" >/dev/null 2>&1 || true; pwd)"
SAMPLE_WORDLIST="$BASE/sample_wordlists/mini-rockyou.txt"
HASH_DIR="$BASE/hashes"
RESULTS_DIR="$BASE/results"
POTFILE="$BASE/results/demo.pot"

mkdir -p "$RESULTS_DIR"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

echo "Using sample wordlist: $SAMPLE_WORDLIST"
if [ ! -f "$SAMPLE_WORDLIST" ]; then
  echo "ERROR: sample wordlist missing. Run generate_hashes.py first."
  exit 1
fi

if [ ! -d "$HASH_DIR" ]; then
  echo "ERROR: hashes directory missing. Run generate_hashes.py first."
  exit 1
fi

# 1) Hashcat (if installed) - MD5 straight wordlist (tiny)
if command_exists hashcat; then
  echo "=== Running Hashcat (MD5 straight) ==="
  HASH_FILE="$HASH_DIR/hashes_md5.txt"
  if [ -f "$HASH_FILE" ]; then
    # -m 0 = MD5, -a 0 = straight
    # --potfile-path set to results demo.pot
    hashcat -m 0 -a 0 "$HASH_FILE" "$SAMPLE_WORDLIST" --potfile-path="$POTFILE" --show --outfile-format=2 --outfile="$RESULTS_DIR/hashcat_md5_cracked.txt" || true
  else
    echo "Skipping Hashcat MD5: $HASH_FILE not found."
  fi
else
  echo "Hashcat not found — skipping Hashcat steps. (Install with: sudo apt install hashcat)"
fi

# 2) Hashcat mask example (small, illustrative)
if command_exists hashcat; then
  echo "=== Hashcat mask example (very small keyspace) ==="
  MASK='?l?l?l?l?l?d'  # 5 lowercase + 1 digit (keeps keyspace small for demo)
  HASH_FILE="$HASH_DIR/hashes_md5.txt"
  if [ -f "$HASH_FILE" ]; then
    # limit runtime with --runtime=10 to keep demo cheap (10s max)
    hashcat -m 0 -a 3 "$HASH_FILE" "$MASK" --potfile-path="$POTFILE" --show --runtime=10 --outfile="$RESULTS_DIR/hashcat_md5_mask.txt" || true
  fi
fi

# 3) John the Ripper (if installed) - try autodetect (safer)
if command_exists john; then
  echo "=== Running John the Ripper (autodetect) ==="
  HASH_FILE="$HASH_DIR/hashes_md5.txt"
  if [ -f "$HASH_FILE" ]; then
    # run with tiny wordlist + rules; let John detect the format
    john --wordlist="$SAMPLE_WORDLIST" --rules "$HASH_FILE" || true
    # save john's show output (plaintext:hash style)
    john --show "$HASH_FILE" > "$RESULTS_DIR/john_md5_show.txt" 2>/dev/null || true
  fi
else
  echo "John the Ripper not found — skipping John steps. (Install with: sudo apt install john)"
fi


# 4) Summarize results to results/cracked.csv (merge of outputs). This is a tiny best-effort merge.
MERGED="$RESULTS_DIR/cracked.csv"
echo "hash_type,hash,plaintext,attack_type,time_s,notes" > "$MERGED"

# Parse hashcat output file format (hashcat --show --outfile-format=2 outputs: hash:plain)
if [ -f "$RESULTS_DIR/hashcat_md5_cracked.txt" ]; then
  while IFS=: read -r h p; do
    echo "MD5,$h,$p,hashcat_wordlist,,generated" >> "$MERGED"
  done < "$RESULTS_DIR/hashcat_md5_cracked.txt"
fi

if [ -f "$RESULTS_DIR/john_md5_show.txt" ]; then
  # john --show prints "plaintext:hash" lines and may include headers; attempt simple parse
  grep -E ':' "$RESULTS_DIR/john_md5_show.txt" | while IFS=: read -r p h _; do
    # if p looks like a hash, swap; safety check naive
    if [[ ${#h} -gt ${#p} ]]; then
      temp="$p"; p="$h"; h="$temp"
    fi
    echo "MD5,$h,$p,john_rules,,generated" >> "$MERGED"
  done
fi

echo "Demo finished. Results (merged): $MERGED"
echo "Reminder: This script uses the tiny sample wordlist for safety. Do not point at real dumps."
