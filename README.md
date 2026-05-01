# GiliSoft .gem Decryptor

Decrypts GiliSoft Video Encryptor `.gem` files to standard `.mp4`.

## Setup

```bash
# 1. Install Python dependency
pip3 install -r requirements.txt

# 2. Install ffmpeg (optional but recommended)
brew install ffmpeg
```

## Usage

```bash
# Single file
python3 decrypt_gem.py lecture.gem

# Batch: entire folder → output folder (only .mp4 in output)
python3 decrypt_gem.py /path/to/input /path/to/output

# Batch: convert in-place (.mp4 saved next to .gem)
python3 decrypt_gem.py /path/to/input
```

## Features

- **Lossless** — no re-encoding, original quality preserved
- **Fast** — ~1 second per 200MB file, parallel processing
- **Skips done** — safe to re-run without redoing work
- **No password needed** — keys extracted from file header
