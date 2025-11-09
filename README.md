🧠 Brainwallet Stream Checker

⚠️ Educational / Research Use Only
This script is intended only for learning, research, and testing your own wallets.
Do not use it to attempt access to wallets, funds, or private keys that you do not own.
The author is not responsible for any misuse or damage caused by this software.

📘 Overview

brainwallet_stream_check.py is a streaming brainwallet scanner that:

reads passphrases line by line from an input text file,

generates multiple private key variants per phrase using SHA-256,

derives Bitcoin P2PKH addresses from those keys,

and optionally checks if any of the generated addresses exist in a local SQLite database (read-only).

If an address is found in the database, the script immediately saves the result to an output file (znalazlem_brainwallet_hits.txt).

⚙️ Features

Streaming mode — does not store results in memory or a local database.

Reads input file line by line (efficient for very large wordlists).

Generates configurable number of variants per phrase (--variants).

Checks addresses against a read-only SQLite database (e.g., alladdresses.db).

Logs any hits immediately to a CSV-style text file.

Periodic progress reports with address generation speed.

🧠 How It Works

For each input phrase:

Compute private key bytes as SHA256(phrase + str(index)) for each variant index.

Derive the corresponding uncompressed public key using secp256k1 (via ecdsa library).

Compute the Bitcoin P2PKH address:

RIPEMD160(SHA256(pubkey))

prepend version byte 0x00

compute Base58Check checksum

encode as Base58 string.

Optionally check if the address exists in the provided SQLite database table addresses(address TEXT).

If a match is found, save timestamp, line number, phrase, address, WIF, and private key hex to the output file.

🧩 Command-Line Usage
python3 brainwallet_stream_check.py \
  -i input_phrases.txt \
  -c alladdresses.db \
  -o hits.csv \
  -v 500 \
  --progress-interval 10000

Option	Description
-i, --input	Input file with one phrase per line
-c, --check-db	SQLite database to check addresses against
-o, --out	Output file for found hits
-v, --variants	Number of variants to generate per phrase
-b, --batch-size	Batch size for progress display
--progress-interval	How often to print progress updates
⚠️ Disclaimer

This code is experimental, untested, and may contain bugs or logic errors.
It is provided AS IS, without any warranty of correctness, fitness, or safety.

It should only be used for:

educational or academic purposes,

testing or auditing your own wallets,

understanding how brainwallets and P2PKH address generation work.

Do not use it for any form of brute-forcing, unauthorized wallet access, or malicious activity.

🧩 Requirements
pip install ecdsa base58


Optionally, you’ll need an existing SQLite database containing a table of Bitcoin addresses:

CREATE TABLE addresses(address TEXT PRIMARY KEY);

📄 License

MIT License — free to use and modify, at your own risk.
Please include a clear educational-use disclaimer in any derived work.

⚠️ Status

🚧 Prototype / Not tested
This script has not been fully tested or verified.
It may produce incorrect results, encounter errors, or fail on large datasets.
Use only in a safe, controlled, offline environment.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
