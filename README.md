# BitRock/CookFS Extractor for TI Processor SDK

Extract files from a TI Processor SDK installer (`.bin`) **without running it** — no root, no GUI, no temp-file cleanup race.

Works by reverse-engineering the embedded BitRock/CookFS payload: parsing the installer's own manifest to locate every file, then reading the CookFS page stream in a single sequential pass.

---

## Background

TI Processor SDK installers are built with [BitRock InstallBuilder](https://installbuilder.com/). The payload is stored as a [CookFS 1.4](https://wiki.tcl-lang.org/page/cookfs) virtual filesystem appended to the ELF binary, followed by a Metakit4 database that holds the manifest, cookfsinfo, and installer scripts.

The installer extracts files to a temp directory and deletes them after installation — making it impossible to intercept the raw archive through normal means.

This script reads the binary directly:

1. Locates the `\x01CFS0002` magic to find the CookFS section and the Metakit4 database.
2. Parses `cookfsinfo.txt` (end offset) and `manifest.txt` (file list with sizes and offsets) from Metakit4.
3. Auto-detects `BIN_OFFSET` (start of payload) from the ELF program headers + file magic scan.
4. Infers the milestone size from the manifest chunk list.
5. Streams the CookFS pages, decompressing raw-deflate chunks on the fly, and writes each file to disk.

---

## Requirements

- Python 3.7+, standard library only (`zlib`, `struct`, `argparse`, `dataclasses`)
- Tested against `ti-processor-sdk-linux-rt-am64xx-evm-11.02.08.02-Linux-x86-Install.bin`

---

## Usage

```
extract_tisdk.py <installer.bin> [options]
```

### Actions (mutually exclusive)

| Option | Description |
|---|---|
| *(default)* | Extract all files from the manifest |
| `-l`, `--list` | List files in the manifest without extracting |
| `-f NAME [NAME …]` | Extract only files whose path contains NAME (case-insensitive) |
| `--dump-meta` | Write `manifest.txt` and `cookfsinfo.txt` to the output directory |

### Output

| Option | Description |
|---|---|
| `-o DIR` | Output directory (default: current directory) |
| `--strip N` | Strip the first N path components (e.g. `--strip 2` turns `default/sdk/foo.tar` → `foo.tar`) |
| `--flatten` | Ignore the full path, extract all files flat into `out-dir` |

### CookFS tuning

Auto-detected by default; override only if needed.

| Option | Description |
|---|---|
| `--bin-offset N` | Byte offset of the CookFS stream (hex accepted: `0x171C4D`) |
| `--block N` | CookFS chunk size in bytes (default: 262144) |
| `--milestone N` | Milestone segment size in bytes (default: inferred from manifest) |

### Misc

| Option | Description |
|---|---|
| `--no-verify` | Skip file size check after extraction |
| `-v`, `--verbose` | Print each filename before extraction |

---

## Examples

```bash
# List all files in the installer
python3 extract_tisdk.py ti-processor-sdk-*.bin --list

# Extract everything to /opt/tisdk
python3 extract_tisdk.py ti-processor-sdk-*.bin -o /opt/tisdk

# Extract only the core bundle, dropping the leading path components
python3 extract_tisdk.py ti-processor-sdk-*.bin -f tisdk-core-bundle --flatten -o /tmp

# Dump the embedded manifest and cookfsinfo for inspection
python3 extract_tisdk.py ti-processor-sdk-*.bin --dump-meta -o /tmp/meta
```

---

## CookFS page format

```
[page_0: block bytes] [sep] [page_1_data] [sep] [page_2_data] …
```

- No separator before the first page.
- `sep = 0x00` → next page is **raw** (uncompressed), read exactly `chunk_size` bytes.
- `sep = 0x01` → next page is **raw-deflate** compressed (`zlib wbits=-15`); over-read and seek back after decompression.
- A **milestone** (default 5 MB) resets the in-segment block counter every N bytes of real data.
- A **block** (default 256 KB) is the maximum uncompressed size per page within a segment.

The milestone size is read directly from the manifest chunk list (all non-last chunks have exactly `milestone` bytes), so no hardcoding is needed.

---

## Limitations

- Only tested on the `am64xx-evm` variant of TI Processor SDK v11.02. Other variants and versions should work if the BitRock/CookFS format is unchanged, but YMMV.
- The script does not verify checksums beyond the final file size. Use `md5sum` or `sha256sum` to cross-check against the reference if needed.
- Only ELF64 installers are supported for auto-detection of `BIN_OFFSET`. Use `--bin-offset` for other formats.
