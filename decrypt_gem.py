#!/usr/bin/env python3
"""
GiliSoft .gem Batch Decryptor
=============================
Recursively decrypts all .gem files from an input folder,
mirroring the directory structure to an output folder.

Usage:
    python3 decrypt_gem.py input.gem [output.mp4]
    python3 decrypt_gem.py /path/to/input /path/to/output
    python3 decrypt_gem.py /path/to/input                   # in-place

Requirements:
    pip3 install pycryptodome
    brew install ffmpeg
"""

import sys
import os
import struct
import subprocess
import shutil
import time
from multiprocessing import Pool, cpu_count
from Crypto.Cipher import AES


def decrypt_one(gem_path, output_path):
    """Decrypt a single .gem → .mp4. Returns (ok, msg)."""
    try:
        with open(gem_path, 'rb') as f:
            data = f.read()

        if data[:6] != b'cpf001':
            return False, "bad magic"

        key = data[0x317D:0x317D + 32]
        iv = bytearray(data[0x357D:0x357D + 16])
        iv[0], iv[15] = iv[15], iv[0]
        iv = bytes(iv)
        iv_int = int.from_bytes(iv, 'big')

        enc = data[0x4000:]
        aligned = (len(enc) // 16) * 16
        dec = bytearray(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(enc[:aligned]))

        if dec[4:8] != b'ftyp':
            return False, "no MP4 header"

        # Fix segmented CBC boundaries (fast int XOR)
        for off in range(0x8000, len(dec), 0x8000):
            if off + 16 > len(dec):
                break
            cp = int.from_bytes(enc[off - 16:off], 'big')
            blk = int.from_bytes(dec[off:off + 16], 'big')
            dec[off:off + 16] = (blk ^ cp ^ iv_int).to_bytes(16, 'big')

        # Trim trailing padding
        pos = 0
        while pos < len(dec) - 8:
            sz = struct.unpack('>I', dec[pos:pos + 4])[0]
            if sz < 8 or sz > len(dec) - pos:
                break
            try:
                dec[pos + 4:pos + 8].decode('ascii')
            except:
                break
            pos += sz
        if pos > 0:
            dec = dec[:pos]

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Remux with ffmpeg
        if shutil.which('ffmpeg'):
            raw = output_path + '.tmp'
            with open(raw, 'wb') as f:
                f.write(dec)
            r = subprocess.run(
                ['ffmpeg', '-y', '-v', 'error', '-i', raw,
                 '-c', 'copy', '-movflags', '+faststart', output_path],
                capture_output=True, timeout=120
            )
            if os.path.exists(raw):
                os.remove(raw)
            if r.returncode != 0 or not os.path.exists(output_path):
                with open(output_path, 'wb') as f:
                    f.write(dec)
        else:
            with open(output_path, 'wb') as f:
                f.write(dec)

        mb = os.path.getsize(output_path) / (1024 * 1024)
        return True, f"{mb:.0f}MB"

    except Exception as e:
        return False, str(e)


def worker(args):
    """Multiprocessing worker."""
    gem, out, idx, total = args
    name = os.path.basename(gem)
    if len(name) > 55:
        name = name[:52] + '...'

    ok, msg = decrypt_one(gem, out)
    tag = "✅" if ok else "❌"
    print(f"  {tag} [{idx}/{total}] {name} → {msg}")
    return ok


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    arg1 = sys.argv[1]
    arg2 = sys.argv[2] if len(sys.argv) > 2 else None

    # --- Single file mode ---
    if os.path.isfile(arg1) and arg1.lower().endswith('.gem'):
        out = arg2 or os.path.splitext(arg1)[0] + '.mp4'
        print(f"📁 {os.path.basename(arg1)} ({os.path.getsize(arg1)/1048576:.0f} MB)")
        ok, msg = decrypt_one(arg1, out)
        print(f"{'✅' if ok else '❌'} {msg}")
        return

    # --- Batch mode ---
    if not os.path.isdir(arg1):
        print(f"❌ Not a file or directory: {arg1}")
        sys.exit(1)

    input_dir = os.path.abspath(arg1)
    output_dir = os.path.abspath(arg2) if arg2 else input_dir

    print(f"📂 Input:  {input_dir}")
    print(f"📂 Output: {output_dir}")

    # Find all .gem files
    gems = []
    for root, _, files in os.walk(input_dir):
        for f in sorted(files):
            if f.lower().endswith('.gem'):
                gems.append(os.path.join(root, f))

    if not gems:
        print("❌ No .gem files found!")
        return

    total_gb = sum(os.path.getsize(g) for g in gems) / (1024 ** 3)
    print(f"📊 Found {len(gems)} files ({total_gb:.1f} GB)\n")

    # Build tasks, skip already done
    tasks = []
    skipped = 0
    for i, gem in enumerate(gems, 1):
        rel = os.path.relpath(gem, input_dir)
        out = os.path.join(output_dir, os.path.splitext(rel)[0] + '.mp4')

        if os.path.exists(out) and os.path.getsize(out) > 1000:
            skipped += 1
            continue
        tasks.append((gem, out, i, len(gems)))

    if skipped:
        print(f"⏭️  Skipping {skipped} already converted\n")

    if not tasks:
        print("✅ All files already converted!")
        return

    # Run in parallel
    workers = min(cpu_count(), len(tasks), 6)
    print(f"🚀 Converting {len(tasks)} files ({workers} parallel workers)\n")

    t0 = time.time()
    with Pool(workers) as pool:
        results = pool.map(worker, tasks)
    elapsed = time.time() - t0

    ok = sum(results)
    fail = len(results) - ok
    speed = (total_gb * 1024) / elapsed if elapsed > 0 else 0

    print(f"\n{'=' * 55}")
    print(f"✅ {ok} converted, ❌ {fail} failed — {elapsed:.0f}s ({speed:.0f} MB/s)")
    if output_dir != input_dir:
        print(f"📂 Output: {output_dir}")


if __name__ == '__main__':
    main()
