#!/usr/bin/env python3
"""
BitRock/CookFS Extractor
Reads the embedded manifest in the installer to auto-detect files,
their names and sizes, then extracts them without running the installer.

CookFS 1.4 format:
  - Sequential chunks from BIN_OFFSET, 1-byte separator between each (not before the first)
    • sep=0x00 : raw (uncompressed) chunk, exactly chunk_size bytes
    • sep=0x01 : raw-deflate compressed chunk, decompresses to chunk_size bytes
  - Segment reset (milestone) every MILESTONE bytes of real data
  - BLOCK = 262144 bytes per chunk within a segment

Usage:
  %(prog)s <installer.bin>              # extract all files
  %(prog)s <installer.bin> -l           # list files
  %(prog)s <installer.bin> -f name.tar  # extract a specific file
  %(prog)s <installer.bin> -o /tmp/out  # output directory
  %(prog)s <installer.bin> --dump-meta  # write manifest.txt and cookfsinfo.txt
"""

import argparse
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# CookFS constants (defaults, overridable via --block / --milestone)
# ---------------------------------------------------------------------------
DEFAULT_BLOCK     = 262_144   # 256 KB per chunk
DEFAULT_MILESTONE = 5_000_000 # segment reset every 5 MB of real data

# CookFS magic and common file magic patterns for BIN_OFFSET detection
CFS_MAGIC = b'\x01CFS0002'
FILE_MAGICS = [
    b'\x1f\x8b\x08',        # gzip
    b'\xfd7zXZ\x00',        # XZ
    b'PK\x03\x04',          # ZIP
    b'BZh9',                 # bzip2
    b'\x04\x22\x4d\x18',   # LZ4
    b'\x89PNG\r\n',          # PNG
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class FileEntry:
    path:        str
    perms:       str
    mtime:       int
    data_offset: int            # byte offset in the CookFS data stream
    chunks:      List[Tuple[int, int]]  # (group_id, size_bytes)
    size:        int            # total size = sum of chunk sizes

@dataclass
class InstallerMeta:
    bin_offset: int
    end_offset: int
    nb_pages:   int
    files:      List[FileEntry]


# ---------------------------------------------------------------------------
# Binary structure detection
# ---------------------------------------------------------------------------
def find_cfs_magic(f) -> Optional[int]:
    """Return the absolute position of \\x01CFS0002 (searched from the end)."""
    f.seek(0, 2)
    fsize = f.tell()
    search = min(60 * 1024 * 1024, fsize)
    f.seek(fsize - search)
    data = f.read(search)
    idx  = data.rfind(CFS_MAGIC)
    return (fsize - search + idx) if idx >= 0 else None


def parse_elf_bin_offset(f) -> Optional[int]:
    """
    Parse ELF 64-bit program headers and return the end of the last PT_LOAD
    segment (approximation of the CookFS section start).
    """
    f.seek(0)
    if f.read(4) != b'\x7fELF':
        return None
    f.seek(4)
    if f.read(1)[0] != 2:        # 64-bit only
        return None

    f.seek(32)
    e_phoff = struct.unpack('<Q', f.read(8))[0]
    f.seek(54)
    e_phentsize, e_phnum = struct.unpack('<HH', f.read(4))

    max_end = 0
    for i in range(e_phnum):
        f.seek(e_phoff + i * e_phentsize)
        ph     = f.read(e_phentsize)
        p_type = struct.unpack_from('<I', ph, 0)[0]
        if p_type == 1:   # PT_LOAD
            p_offset = struct.unpack_from('<Q', ph, 8)[0]
            p_filesz = struct.unpack_from('<Q', ph, 32)[0]
            max_end  = max(max_end, p_offset + p_filesz)
    return max_end or None


def detect_bin_offset(f, elf_end: int, window: int = 4096) -> Optional[int]:
    """
    Search for the first known file magic in a window after elf_end.
    Return the absolute position of the first CookFS data byte.
    """
    f.seek(elf_end)
    buf = f.read(window)
    best = None
    for magic in FILE_MAGICS:
        idx = buf.find(magic)
        if idx >= 0 and (best is None or idx < best):
            best = idx
    return (elf_end + best) if best is not None else None


# ---------------------------------------------------------------------------
# Metakit4 section parsing
# ---------------------------------------------------------------------------
def scan_zlib_streams(data: bytes) -> List[Tuple[int, bytes]]:
    """Return [(offset, decompressed_content)] for every zlib stream found."""
    results   = []
    zlib_heads = {(0x78, b) for b in (0x01, 0x5e, 0x9c, 0xda)}
    pos = 0
    while pos < len(data) - 1:
        if (data[pos], data[pos + 1]) in zlib_heads:
            try:
                results.append((pos, zlib.decompress(data[pos:pos + 524288])))
                pos += 2
                continue
            except zlib.error:
                pass
        pos += 1
    return results


def find_metakit_text_files(f, mk4_start: int) -> Tuple[Optional[str], Optional[str]]:
    """
    Read up to 6 MB of the Metakit4 section and heuristically extract:
      - cookfsinfo.txt  (contains '-endoffset')
      - manifest.txt    (contains '{file …}' entries)
    Return (cookfsinfo_text, manifest_text).
    """
    f.seek(mk4_start)
    mk4_data = f.read(6 * 1024 * 1024)

    cookfsinfo = None
    manifest   = None

    for _pos, content in scan_zlib_streams(mk4_data):
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            continue

        stripped = text.strip()

        # cookfsinfo.txt: must contain '-endoffset' followed by a real integer
        if cookfsinfo is None and '-endoffset' in stripped:
            tokens = stripped.split()
            for i, tok in enumerate(tokens):
                if tok == '-endoffset' and i + 1 < len(tokens):
                    try:
                        int(tokens[i + 1])
                        cookfsinfo = stripped
                    except ValueError:
                        pass   # Tcl template ($opt(endoffset)), skip
                    break

        # manifest.txt: lines of the form "path {file …}" or "path {directory …}"
        if manifest is None:
            lines = stripped.splitlines()
            if lines and any(' {file ' in ln or ' {directory ' in ln
                             for ln in lines[:10]):
                manifest = stripped

    # Fallback: cookfsinfo.txt may be stored as plain text (non-zlib) in Metakit4
    if cookfsinfo is None:
        idx = mk4_data.find(b'-endoffset')
        if idx >= 0:
            raw = mk4_data[idx:idx + 256]
            end = raw.find(b'\x00')
            cookfsinfo = raw[:end if end >= 0 else 256].decode('utf-8', errors='replace').strip()

    return cookfsinfo, manifest


def parse_cookfsinfo(text: str) -> dict:
    """Parse '-key value -key value …' into a dict."""
    result, tokens = {}, text.split()
    for i in range(0, len(tokens) - 1, 2):
        result[tokens[i].lstrip('-')] = tokens[i + 1]
    return result


# ---------------------------------------------------------------------------
# Minimal Tcl list tokenizer
# ---------------------------------------------------------------------------
def tcl_split(s: str) -> List[str]:
    """
    Split a Tcl string into tokens, handling {nested braces}
    and "double quotes".
    """
    tokens, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
        elif c == '{':
            depth, j = 0, i
            while j < n:
                if   s[j] == '{': depth += 1
                elif s[j] == '}':
                    depth -= 1
                    if depth == 0:
                        tokens.append(s[i + 1:j])
                        i = j + 1
                        break
                j += 1
            else:
                tokens.append(s[i + 1:])   # unclosed brace — be lenient
                i = n
        elif c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                if s[j] == '\\':
                    j += 1
                j += 1
            tokens.append(s[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < n and not s[j].isspace() and s[j] not in ('{', '}', '"'):
                j += 1
            tokens.append(s[i:j])
            i = j
    return tokens


def _parse_chunks(s: str) -> List[Tuple[int, int]]:
    """
    '{group size} {group size} …'  →  [(group, size), …]
    (group is a CookFS page group id, size is the chunk size in bytes)
    """
    chunks = []
    for token in tcl_split(s):
        parts = token.strip().split()
        if len(parts) >= 2:
            try:
                chunks.append((int(parts[0]), int(parts[1])))
            except ValueError:
                pass
    return chunks


def parse_manifest(text: str) -> List[FileEntry]:
    """
    Parse the CookFS/BitRock manifest.txt into a list of FileEntry objects.

    Line format:
      path {file perms mtime data_offset {{group size} …}}
      path {directory perms mtime}
    """
    entries: List[FileEntry] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        tokens = tcl_split(line)
        if len(tokens) < 2:
            continue

        path = tokens[0]
        info = tcl_split(tokens[1])
        if not info:
            continue

        ftype = info[0]
        perms = info[1] if len(info) > 1 else '644'
        mtime = int(info[2]) if len(info) > 2 else 0

        if ftype == 'file':
            data_offset = int(info[3]) if len(info) > 3 else 0
            chunks_str  = info[4]     if len(info) > 4 else ''
            chunks      = _parse_chunks(chunks_str)
            size        = sum(c[1] for c in chunks)
            entries.append(FileEntry(
                path=path, perms=perms, mtime=mtime,
                data_offset=data_offset, chunks=chunks, size=size,
            ))
        elif ftype == 'directory':
            # Directories take no space in the CookFS stream
            entries.append(FileEntry(
                path=path, perms=perms, mtime=mtime,
                data_offset=0, chunks=[], size=0,
            ))

    return entries


# ---------------------------------------------------------------------------
# Milestone inference from manifest
# ---------------------------------------------------------------------------
def infer_milestone(files: List[FileEntry]) -> Optional[int]:
    """
    Derive the milestone size from the manifest chunk list.

    All non-last chunks of every file have exactly milestone bytes, so the
    milestone equals the maximum chunk size seen across all files.
    Returns None if no chunk data is available.
    """
    best = None
    for entry in files:
        for _, size in entry.chunks:
            if best is None or size > best:
                best = size
    return best


# ---------------------------------------------------------------------------
# Output path construction
# ---------------------------------------------------------------------------
def make_out_path(entry: FileEntry, out_dir: str,
                  strip: int, flatten: bool) -> str:
    parts = entry.path.replace('\\', '/').split('/')
    if strip:
        parts = parts[min(strip, len(parts) - 1):]
    if flatten:
        parts = [parts[-1]] if parts else ['unknown']
    return os.path.join(out_dir, *parts)


# ---------------------------------------------------------------------------
# Extraction core: reading the CookFS stream
# ---------------------------------------------------------------------------
def _close_entry(info: dict, no_verify: bool) -> None:
    """Close the current output file and print the verification result."""
    info['f_out'].close()
    entry    = info['entry']
    out_size = os.path.getsize(info['path'])
    ok       = out_size == entry.size
    status   = '✓' if ok else '✗'
    if ok:
        print(f'{status} {info["path"]}  ({out_size:,} bytes)')
    else:
        print(f'{status} {info["path"]}  ({out_size:,} bytes, expected {entry.size:,})',
              file=sys.stderr)


def extract_stream(
    f_bin,
    files:     List[FileEntry],
    out_dir:   str,
    bin_offset: int,
    block:     int,
    milestone: int,
    strip:     int  = 0,
    flatten:   bool = False,
    no_verify: bool = False,
    verbose:   bool = False,
) -> None:
    """
    Read the CookFS stream from BIN_OFFSET and extract the requested files.

    Files are sorted by ascending data_offset; the stream is read
    sequentially in a single pass.
    """
    if not files:
        return

    sorted_files = sorted(files, key=lambda e: e.data_offset)
    stream_end   = sorted_files[-1].data_offset + sorted_files[-1].size

    f_bin.seek(bin_offset)

    stream_pos = 0
    seg_start  = 0
    cur_type   = 0x00   # the first chunk has no preceding separator

    file_queue  = list(sorted_files)
    cur_out     = None  # {'entry', 'f_out', 'path', 'written'}
    bytes_written = 0
    next_progress = 100 * 1024 * 1024

    while stream_pos < stream_end:
        # ------------------------------------------------------------------
        # Compute next chunk boundaries
        # ------------------------------------------------------------------
        pos_in_seg = stream_pos - seg_start
        next_block = seg_start + ((pos_in_seg // block) + 1) * block
        next_mile  = seg_start + milestone
        next_sep   = min(next_block, next_mile)
        chunk_size = min(next_sep - stream_pos, stream_end - stream_pos)

        # ------------------------------------------------------------------
        # Read chunk (raw or deflated)
        # ------------------------------------------------------------------
        if cur_type == 0x00:
            data = f_bin.read(chunk_size)
            if len(data) != chunk_size:
                raise IOError(
                    f'Short read at stream_pos={stream_pos}: '
                    f'expected {chunk_size}, got {len(data)}')

        elif cur_type == 0x01:
            over  = block + 65536
            raw   = f_bin.read(over)
            dobj  = zlib.decompressobj(-15)
            data  = dobj.decompress(raw)
            if len(data) != chunk_size:
                raise ValueError(
                    f'Invalid decompression at stream_pos={stream_pos}: '
                    f'{len(data)} bytes, expected {chunk_size}')
            if dobj.unused_data:
                f_bin.seek(-len(dobj.unused_data), 1)

        else:
            raise ValueError(
                f'Unknown chunk type: 0x{cur_type:02x} '
                f'at stream_pos={stream_pos}')

        # ------------------------------------------------------------------
        # Distribute chunk data to output files
        # ------------------------------------------------------------------
        data_pos = 0
        while data_pos < chunk_size:
            abs_pos = stream_pos + data_pos

            # Open next file if we have reached its start
            if cur_out is None and file_queue:
                entry = file_queue[0]
                if abs_pos >= entry.data_offset:
                    file_queue.pop(0)
                    if entry.size > 0:          # skip directories / zero-size entries
                        out_path = make_out_path(entry, out_dir, strip, flatten)
                        parent   = os.path.dirname(os.path.abspath(out_path))
                        os.makedirs(parent, exist_ok=True)
                        cur_out = {
                            'entry':   entry,
                            'f_out':   open(out_path, 'wb'),
                            'path':    out_path,
                            'written': 0,
                        }
                        if verbose:
                            print(f'  → {out_path}  ({entry.size:,} bytes)',
                                  flush=True)

            if cur_out is None:
                # Skip ahead to next file or end of chunk
                if file_queue:
                    gap = min(file_queue[0].data_offset - abs_pos,
                              chunk_size - data_pos)
                    if gap > 0:
                        data_pos += gap
                else:
                    data_pos = chunk_size
                continue

            # Write as many bytes as possible to the current file
            entry     = cur_out['entry']
            remaining = entry.size - cur_out['written']
            to_write  = min(remaining, chunk_size - data_pos)

            cur_out['f_out'].write(data[data_pos:data_pos + to_write])
            cur_out['written'] += to_write
            bytes_written      += to_write
            data_pos           += to_write

            if cur_out['written'] >= entry.size:
                _close_entry(cur_out, no_verify)
                cur_out = None

        # ------------------------------------------------------------------
        # Separator (indicates the type of the NEXT chunk)
        # ------------------------------------------------------------------
        stream_pos += chunk_size
        if stream_pos < stream_end:
            sep = f_bin.read(1)
            if not sep:
                raise IOError(
                    f'Unexpected EOF reading separator at stream_pos={stream_pos}')
            cur_type = sep[0]
            if cur_type not in (0x00, 0x01):
                print(f'[WARN] Unexpected separator 0x{cur_type:02x} '
                      f'at stream_pos={stream_pos}', file=sys.stderr)
            if stream_pos == next_mile:
                seg_start = stream_pos

        # ------------------------------------------------------------------
        # Progress display
        # ------------------------------------------------------------------
        if bytes_written >= next_progress:
            span = stream_end - sorted_files[0].data_offset
            done = stream_pos - sorted_files[0].data_offset
            pct  = done / span * 100 if span else 100
            print(f'  {done / 1e9:.2f} / {span / 1e9:.2f} GB  ({pct:.1f}%)',
                  flush=True)
            next_progress += 100 * 1024 * 1024

    if cur_out:
        _close_entry(cur_out, no_verify)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Source file
    parser.add_argument(
        'binary',
        help='BitRock installer binary (.bin)')

    # Mutually exclusive actions
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        '-l', '--list', action='store_true',
        help='List files in the manifest without extracting')
    action.add_argument(
        '-f', '--file', nargs='+', metavar='NAME',
        help='Extract only files whose path contains NAME '
             '(case-insensitive, matched against full path or basename)')
    action.add_argument(
        '--dump-meta', action='store_true',
        help='Write manifest.txt and cookfsinfo.txt to out-dir and exit')

    # Output destination
    parser.add_argument(
        '-o', '--out-dir', default='.', metavar='DIR',
        help='Output directory (default: current directory)')
    parser.add_argument(
        '--strip', type=int, default=0, metavar='N',
        help='Strip the first N path components from the output path '
             '(e.g. --strip 2 turns default/sdk/foo.tar into foo.tar)')
    parser.add_argument(
        '--flatten', action='store_true',
        help='Ignore the full path, extract all files flat into out-dir')

    # CookFS parameters (auto-detected by default)
    parser.add_argument(
        '--bin-offset', type=lambda x: int(x, 0), default=None, metavar='N',
        help='Byte offset of the CookFS stream start (hex accepted: 0x171C4D). '
             'Auto-detected from ELF + file magic if omitted.')
    parser.add_argument(
        '--block', type=int, default=DEFAULT_BLOCK, metavar='N',
        help=f'CookFS chunk size in bytes (default: {DEFAULT_BLOCK})')
    parser.add_argument(
        '--milestone', type=int, default=None, metavar='N',
        help=f'Milestone segment size in bytes (default: inferred from manifest, '
             f'fallback {DEFAULT_MILESTONE})')

    # Miscellaneous
    parser.add_argument(
        '--no-verify', action='store_true',
        help='Skip file size verification after extraction')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Verbose output (print filename before extraction)')

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        sys.exit(f'Error: file not found: {args.binary}')

    # -----------------------------------------------------------------------
    # Phase 1: Binary analysis
    # -----------------------------------------------------------------------
    print(f'Analysing {os.path.basename(args.binary)} ...')

    with open(args.binary, 'rb') as f:

        # 1a. CookFS magic → start of Metakit4 section
        cfs_pos = find_cfs_magic(f)
        if cfs_pos is None:
            sys.exit('Error: CookFS magic (\\x01CFS0002) not found in binary.')
        mk4_start = cfs_pos + len(CFS_MAGIC)

        # 1b. CookFS footer (8 bytes before magic): nb_pages, idx_size
        f.seek(cfs_pos - 8)
        footer   = f.read(8)
        idx_size = struct.unpack('>I', footer[:4])[0]
        nb_pages = struct.unpack('>I', footer[4:])[0]

        print(f'  CookFS magic   @ 0x{cfs_pos:x}')
        print(f'  Page count     : {nb_pages}   Index: {idx_size} bytes')
        print(f'  Metakit4       @ 0x{mk4_start:x}')

        # 1c. Read cookfsinfo.txt and manifest.txt from Metakit4
        cookfsinfo_txt, manifest_txt = find_metakit_text_files(f, mk4_start)

        if manifest_txt is None:
            sys.exit('Error: manifest.txt not found in Metakit4 section.')

        end_offset = cfs_pos + 8   # default value
        if cookfsinfo_txt:
            info = parse_cookfsinfo(cookfsinfo_txt)
            if 'endoffset' in info:
                end_offset = int(info['endoffset'])
            print(f'  cookfsinfo     : endoffset={end_offset}')

        # 1d. BIN_OFFSET (manual override or auto-detection)
        if args.bin_offset is not None:
            bin_offset = args.bin_offset
            print(f'  BIN_OFFSET     : 0x{bin_offset:x}  (manual)')
        else:
            elf_end = parse_elf_bin_offset(f)
            if elf_end is None:
                sys.exit(
                    'Error: non-ELF binary and --bin-offset not provided.\n'
                    'Use --bin-offset <value> to specify the offset manually.')

            bin_offset = detect_bin_offset(f, elf_end)
            if bin_offset is None:
                bin_offset = elf_end
                print(f'  BIN_OFFSET     : 0x{bin_offset:x}  '
                      f'(ELF end, file magic not found — verify with --bin-offset)',
                      file=sys.stderr)
            else:
                print(f'  BIN_OFFSET     : 0x{bin_offset:x}  '
                      f'(ELF+{bin_offset - elf_end} bytes)')

    # 1e. Parse manifest
    all_files = [e for e in parse_manifest(manifest_txt) if e.size > 0]
    print(f'  Manifest       : {len(all_files)} file(s)')

    if args.milestone is not None:
        milestone = args.milestone
        print(f'  Milestone      : {milestone} bytes (manual)')
    else:
        milestone = infer_milestone(all_files) or DEFAULT_MILESTONE
        source = 'manifest' if infer_milestone(all_files) else 'default'
        print(f'  Milestone      : {milestone} bytes ({source})')

    # -----------------------------------------------------------------------
    # Phase 2: Dump meta mode
    # -----------------------------------------------------------------------
    if args.dump_meta:
        os.makedirs(args.out_dir, exist_ok=True)
        for filename, content in (
            ('manifest.txt',   manifest_txt),
            ('cookfsinfo.txt', cookfsinfo_txt),
        ):
            if content is None:
                print(f'  [skip] {filename} not found', file=sys.stderr)
                continue
            out_path = os.path.join(args.out_dir, filename)
            with open(out_path, 'w', encoding='utf-8') as fh:
                fh.write(content)
                if not content.endswith('\n'):
                    fh.write('\n')
            print(f'  → {out_path}  ({len(content.encode())} bytes)')
        return

    # -----------------------------------------------------------------------
    # Phase 3: List mode
    # -----------------------------------------------------------------------
    if args.list:
        from datetime import datetime
        print()
        print(f'  {"Path":<65} {"Size":>15}  Date')
        print('  ' + '-' * 90)
        for e in sorted(all_files, key=lambda x: x.path):
            dt = datetime.fromtimestamp(e.mtime).strftime('%Y-%m-%d %H:%M')
            print(f'  {e.path:<65} {e.size:>15,}  {dt}')
        return

    # -----------------------------------------------------------------------
    # Phase 4: Select files to extract
    # -----------------------------------------------------------------------
    if args.file:
        filters = [f.lower() for f in args.file]
        to_extract = [
            e for e in all_files
            if any(
                filt in e.path.lower() or
                filt in os.path.basename(e.path).lower()
                for filt in filters
            )
        ]
        if not to_extract:
            sys.exit(
                f'No files matching: {args.file}\n'
                f'Use --list to see available files.')
        if len(to_extract) < len(args.file):
            print(f'[WARN] Only {len(to_extract)}/{len(args.file)} '
                  f'file(s) matched.', file=sys.stderr)
    else:
        to_extract = all_files

    print(f'\nExtracting {len(to_extract)} file(s) '
          f'to {os.path.abspath(args.out_dir)}/')
    os.makedirs(args.out_dir, exist_ok=True)

    # -----------------------------------------------------------------------
    # Phase 5: Extraction
    # -----------------------------------------------------------------------
    with open(args.binary, 'rb') as f:
        extract_stream(
            f_bin      = f,
            files      = to_extract,
            out_dir    = args.out_dir,
            bin_offset = bin_offset,
            block      = args.block,
            milestone  = milestone,
            strip      = args.strip,
            flatten    = args.flatten,
            no_verify  = args.no_verify,
            verbose    = args.verbose,
        )


if __name__ == '__main__':
    main()
