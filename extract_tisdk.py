#!/usr/bin/env python3
"""
BitRock/CookFS extractor for ti-processor-sdk
Format: BIN_OFFSET then sequential chunks with a separator BETWEEN each chunk
  - sep=0x00: next chunk is raw (chunk_size bytes)
  - sep=0x01: next chunk is raw-deflate compressed (variable size → chunk_size bytes)
Milestone every 5 MB: reset the block counter (262144 bytes per block).
"""
import zlib
import sys
import os

BIN_FILE = 'ti-processor-sdk-linux-rt-am64xx-evm-11.02.08.02-Linux-x86-Install.bin'
OUT_FILE = 'tisdk-core-bundle-am64xx-evm.extracted.tar.xz'

BIN_OFFSET = 0x171C4D       # 1,514,573 – CookFS section start
BLOCK      = 262144          # uncompressed chunk size (256 KB)
MILESTONE  = 5_000_000       # segment reset every 5 MB of real data
REAL_SIZE  = 2_188_699_015   # exact size of the target file

PROGRESS_INTERVAL = 100 * 1024 * 1024  # report progress every 100 MB

def extract():
    total = REAL_SIZE
    written = 0
    next_report = PROGRESS_INTERVAL

    with open(BIN_FILE, 'rb') as f_bin, open(OUT_FILE, 'wb') as f_out:
        f_bin.seek(BIN_OFFSET)

        real_pos  = 0
        seg_start = 0
        # First chunk has no preceding separator → implicit type 0x00
        current_type = 0x00

        while real_pos < total:
            # Compute next chunk size
            pos_in_seg = real_pos - seg_start
            next_block = seg_start + ((pos_in_seg // BLOCK) + 1) * BLOCK
            next_mile  = seg_start + MILESTONE
            next_sep   = min(next_block, next_mile)
            chunk_size = min(next_sep - real_pos, total - real_pos)

            # Read chunk
            if current_type == 0x00:
                data = f_bin.read(chunk_size)
                if len(data) != chunk_size:
                    raise IOError(f'Short read at real_pos={real_pos}: '
                                  f'expected {chunk_size}, got {len(data)}')

            elif current_type == 0x01:
                # Raw deflate; compressed size unknown → over-read then seek back
                over = BLOCK + 65536  # more than enough
                raw  = f_bin.read(over)
                d    = zlib.decompressobj(-15)
                data = d.decompress(raw)
                if len(data) != chunk_size:
                    raise ValueError(
                        f'Decompression: got {len(data)} bytes, expected {chunk_size}')
                # Reposition pointer right after consumed compressed data
                unused = len(d.unused_data)
                if unused:
                    f_bin.seek(-unused, 1)

            else:
                raise ValueError(f'Unknown chunk type: 0x{current_type:02x} '
                                  f'at real_pos={real_pos}')

            f_out.write(data)
            real_pos += chunk_size
            written  += chunk_size

            # Separator (indicates the type of the NEXT chunk)
            if real_pos < total:
                sep = f_bin.read(1)
                if not sep:
                    raise IOError(f'Unexpected EOF reading separator at real_pos={real_pos}')
                current_type = sep[0]
                if current_type not in (0x00, 0x01):
                    print(f'[WARN] Unexpected separator 0x{current_type:02x} '
                          f'at real_pos={real_pos}', file=sys.stderr)

                # Segment reset when crossing a milestone
                if real_pos == next_mile:
                    seg_start = real_pos

            # Progress
            if written >= next_report:
                pct = written / total * 100
                print(f'  {written / 1e9:.2f} GB / {total / 1e9:.2f} GB ({pct:.1f}%)')
                next_report += PROGRESS_INTERVAL

    print(f'Extraction complete: {written} bytes → {OUT_FILE}')
    out_size = os.path.getsize(OUT_FILE)
    print(f'Written file size: {out_size}')
    if out_size == REAL_SIZE:
        print('✓ Size correct')
    else:
        print(f'✗ Incorrect size (expected {REAL_SIZE})')

if __name__ == '__main__':
    extract()
