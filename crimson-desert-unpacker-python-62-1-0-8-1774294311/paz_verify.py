"""Verify a repacked PAZ entry by reading it back, decrypting, and decompressing.

Reads the bytes at the recorded offset/size from the PAZ file, decrypts and
decompresses them, then compares the result against the expected modified file.

Usage:
    python paz_verify.py <modified.xml> --pamt 0.pamt --paz-dir ./0000 \
        --entry "object/terrainheightfieldregioninfonew.xml"
"""

import sys
import argparse
import lz4.block

from paz_parse import parse_pamt
from paz_crypto import decrypt
from paz_repack import find_entry


def verify_entry(modified_path: str, pamt_path: str, paz_dir: str, entry_path: str):
    entries = parse_pamt(pamt_path, paz_dir=paz_dir)
    entry = find_entry(entries, entry_path)

    print(f"Entry:     {entry.path}")
    print(f"PAZ:       {entry.paz_file} @ 0x{entry.offset:08X}")
    print(f"comp_size: {entry.comp_size:,}")
    print(f"orig_size: {entry.orig_size:,}")
    print()

    # Read back from PAZ
    with open(entry.paz_file, 'rb') as f:
        f.seek(entry.offset)
        raw = f.read(entry.comp_size)

    print(f"Read {len(raw):,} bytes from PAZ")

    # Decrypt
    if entry.encrypted:
        import os
        basename = os.path.basename(entry.path)
        raw = decrypt(raw, basename)
        print("Decrypted OK")

    # Decompress
    if entry.compressed and entry.compression_type == 2:
        try:
            decompressed = lz4.block.decompress(raw, uncompressed_size=entry.orig_size)
            print(f"Decompressed OK: {len(decompressed):,} bytes")
        except Exception as e:
            print(f"DECOMPRESSION FAILED: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        decompressed = raw

    # Compare against modified file
    with open(modified_path, 'rb') as f:
        expected = f.read()

    # The decompressed data may be zero-padded to orig_size
    decompressed_trimmed = decompressed.rstrip(b'\x00')

    # Check if the modified content is present (ignoring padding/inflation bytes)
    if decompressed[:len(expected)] == expected:
        print(f"MATCH: first {len(expected):,} bytes match modified file exactly")
    else:
        # Find first difference
        for i, (a, b) in enumerate(zip(decompressed, expected)):
            if a != b:
                ctx_start = max(0, i - 40)
                ctx_end = min(len(expected), i + 40)
                print(f"MISMATCH at byte {i:,}")
                print(f"  PAZ:      {decompressed[ctx_start:ctx_end]!r}")
                print(f"  Expected: {expected[ctx_start:ctx_end]!r}")
                break
        else:
            print(f"PAZ has {len(decompressed):,} bytes, modified has {len(expected):,} bytes")
            if len(decompressed) > len(expected):
                extra = decompressed[len(expected):]
                non_null = bytes(b for b in extra if b != 0)
                print(f"Extra {len(extra):,} bytes after modified content "
                      f"({len(non_null):,} non-null)")
                if non_null:
                    print(f"  First extra bytes: {extra[:80]!r}")
        sys.exit(1)

    # Show a snippet of the decompressed content around the end of modified data
    snippet_start = max(0, len(expected) - 100)
    snippet_end = min(len(decompressed), len(expected) + 100)
    print(f"\nContent around boundary (bytes {snippet_start}-{snippet_end}):")
    print(repr(decompressed[snippet_start:snippet_end]))


def main():
    parser = argparse.ArgumentParser(description="Verify a repacked PAZ entry")
    parser.add_argument("modified", help="Path to the modified file you repacked")
    parser.add_argument("--pamt", required=True, help="Path to .pamt index file")
    parser.add_argument("--paz-dir", help="Directory containing .paz files")
    parser.add_argument("--entry", required=True, help="Entry path within the archive")
    args = parser.parse_args()

    verify_entry(args.modified, args.pamt, args.paz_dir, args.entry)


if __name__ == "__main__":
    main()
