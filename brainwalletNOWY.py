#!/usr/bin/env python3
# coding: utf-8
"""
brainwallet_stream_check.py
- streaming: generuje warianty per-line, sprawdza je w istniejącej bazie SQLite (read-only)
- nie zapisuje wygenerowanych rekordów do lokalnej bazy (oszczędność RAM/dysku)
- jeśli trafienie -> zapisuje natychmiast do pliku wynikowego
"""
import sys
import os
import time
import hashlib
import sqlite3
from ecdsa import SigningKey, SECP256k1
import argparse

# ---------- Konfiguracja domyślna ----------
CHECK_DB_DEFAULT = "alladdresses.db"        # baza do sprawdzania (must exist)
FOUND_FILENAME = "znalazlem_brainwallet_hits.txt"
VARIANTS_DEFAULT = 1000
BATCH_SIZE_DEFAULT = 1000        # ile fraz na "partię" tylko na cel statystyk/progresu
PROGRESS_INTERVAL = 10000       # co ile wygenerowanych adresów raportować
CURVE = SECP256k1
DB_TIMEOUT = 5

# ---------- Crypto helpers ----------
def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def private_key_from_phrase_variant(phrase: str, index: int) -> bytes:
    if phrase == "<EMPTY>":
        phrase = ""
    if index == 0:
        return hashlib.sha256(phrase.encode("utf-8")).digest()
    else:
        return hashlib.sha256((phrase + str(index)).encode("utf-8")).digest()

def pubkey_uncompressed_from_priv(priv_bytes: bytes) -> bytes:
    sk = SigningKey.from_string(priv_bytes, curve=CURVE)
    vk = sk.get_verifying_key()
    xy = vk.to_string()
    return b'\x04' + xy

def p2pkh_address_from_pubkey(pubkey_bytes: bytes) -> str:
    sha = hashlib.sha256(pubkey_bytes).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    payload = b"\x00" + rip
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    import base58
    return base58.b58encode(payload + checksum).decode("utf-8")

def wif_from_priv(priv_bytes: bytes) -> str:
    prefix = b"\x80" + priv_bytes
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    import base58
    return base58.b58encode(prefix + checksum).decode("utf-8")

# ---------- DB helpers ----------
def open_check_db_ro(path: str):
    if not os.path.isfile(path):
        print(f"[!] Check DB not found: {path}")
        return None
    uri = f"file:{path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=DB_TIMEOUT, check_same_thread=False)
    # perf pragmas (read-only DB) - these can help a bit
    try:
        conn.execute("PRAGMA journal_mode=OFF;")
        conn.execute("PRAGMA synchronous=OFF;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")  # 256MB if supported
    except Exception:
        pass
    return conn

def address_exists_stmt(conn, address):
    # prepared single-row query; assumes idx on addresses.address exists
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM addresses WHERE address = ? LIMIT 1", (address,))
    return cur.fetchone() is not None

# ---------- Main processing ----------
def process_stream(input_path: str, check_db_path: str, out_hits_path: str,
                   variants: int, batch_size: int, progress_interval: int):
    check_conn = open_check_db_ro(check_db_path) if check_db_path else None
    if check_conn:
        print(f"[DB] Connected read-only to {check_db_path}")
    else:
        print("[DB] No check DB provided or could not open — running without check (will only generate).")

    total_generated = 0
    total_lines = 0
    hits = 0
    t0 = time.time()

    with open(input_path, "r", encoding="utf-8", errors="ignore") as inf, \
         open(out_hits_path, "a", encoding="utf-8") as fout:

        batch_count = 0
        for lineno, raw in enumerate(inf, start=1):
            phrase = raw.rstrip("\n")
            if phrase == "":
                continue

            # dla każdego wariantu generujemy, sprawdzamy natychmiast i ewentualnie zapisujemy
            for i in range(variants):
                try:
                    priv = private_key_from_phrase_variant(phrase, i)
                    pub = pubkey_uncompressed_from_priv(priv)
                    addr = p2pkh_address_from_pubkey(pub)
                    total_generated += 1

                    if check_conn:
                        try:
                            if address_exists_stmt(check_conn, addr):
                                wif = wif_from_priv(priv)
                                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                                fout.write(f"{stamp},{lineno},{i},{phrase},{addr},{wif},{priv.hex()}\n")
                                fout.flush()
                                hits += 1
                                print(f"[HIT] line={lineno} #{i} -> {addr}")
                                # Immediately drop priv/pub variables (they go out of scope) - memory freed naturally
                        except Exception as e:
                            print(f"[!] DB check error on {addr}: {e}")
                    # progress
                    if total_generated % progress_interval == 0:
                        elapsed = time.time() - t0
                        rate = total_generated / elapsed if elapsed > 0 else 0
                        print(f"[⏳] Generated {total_generated:,} addresses (~{rate:,.0f}/s), hits={hits}")
                except Exception as e:
                    print(f"[ERROR] at line {lineno} variant {i}: {e}")

            batch_count += 1
            total_lines += 1
            # optional small progress print per batch
            if batch_count % max(1, (batch_size // 10)) == 0:
                print(f"[batch] processed {total_lines} input lines (last line {lineno}), total_generated={total_generated:,}, hits={hits}")

    if check_conn:
        check_conn.close()
    elapsed = time.time() - t0
    print(f"\nDone. Generated {total_generated:,} addresses in {elapsed:.1f}s (~{total_generated/elapsed:,.0f}/s). Hits={hits}")
    print(f"Hits saved to: {out_hits_path}")

# ---------- CLI ----------
def cli():
    ap = argparse.ArgumentParser(description="Stream brainwallet variants, check addresses against SQLite DB (read-only).")
    ap.add_argument('-i','--input', required=True, help='input file (one passphrase per line)')
    ap.add_argument('-c','--check-db', default=CHECK_DB_DEFAULT, help='SQLite DB to check addresses against (read-only)')
    ap.add_argument('-o','--out', default=FOUND_FILENAME, help='output file for found hits (CSV lines)')
    ap.add_argument('-v','--variants', type=int, default=VARIANTS_DEFAULT, help='variants per passphrase (0..N)')
    ap.add_argument('-b','--batch-size', type=int, default=BATCH_SIZE_DEFAULT, help='batch size (only for progress prints)')
    ap.add_argument('--progress-interval', type=int, default=PROGRESS_INTERVAL, help='report every N generated addresses')
    args = ap.parse_args()
    process_stream(args.input, args.check_db, args.out, args.variants, args.batch_size, args.progress_interval)

if __name__ == "__main__":
    cli()
