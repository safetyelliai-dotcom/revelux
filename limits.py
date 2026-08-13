"""
Resource limits for parsing hostile input.

Revelux is pointed at files precisely because they are not trusted yet, so
its own parsers are an attack surface: every parser here reads whole parts
into memory, and the OOXML formats are zip archives whose contents can
expand by orders of magnitude. Without a ceiling, a few-KB decompression
bomb dropped into a scanned folder stops the scan - and, if Revelux is
gating an ingestion pipeline, whatever sits behind it.

Limits are deliberately generous: real documents rarely approach them, so
hitting one is itself a signal worth surfacing rather than a routine event.
Exceeding a limit raises LimitExceeded, which scanner.py surfaces as an
ERROR for that file - never as CLEAN, since an unscanned file has not been
cleared of anything.
"""

import os
import zipfile

MAX_FILE_BYTES = 100 * 1024 * 1024          # 100 MB on disk
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB expanded out of a zip
MAX_COMPRESSION_RATIO = 200                 # expanded / stored


class LimitExceeded(Exception):
    """A file exceeded a resource limit and was not scanned."""


def configure(max_file_bytes=None, max_uncompressed_bytes=None, max_ratio=None):
    """Override the defaults (used by the CLIs' --max-* flags)."""
    global MAX_FILE_BYTES, MAX_UNCOMPRESSED_BYTES, MAX_COMPRESSION_RATIO
    if max_file_bytes is not None:
        MAX_FILE_BYTES = max_file_bytes
    if max_uncompressed_bytes is not None:
        MAX_UNCOMPRESSED_BYTES = max_uncompressed_bytes
    if max_ratio is not None:
        MAX_COMPRESSION_RATIO = max_ratio


def _mb(n):
    return f"{n / (1024 * 1024):.1f} MB"


def check_file_size(path):
    """Reject a file that is too large to read into memory safely."""
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise LimitExceeded(
            f"file is {_mb(size)}, above the {_mb(MAX_FILE_BYTES)} limit - not scanned"
        )
    return size


def check_payload_size(nbytes, label="payload"):
    """Same check for bytes already in memory (e.g. an email attachment)."""
    if nbytes > MAX_FILE_BYTES:
        raise LimitExceeded(
            f"{label} is {_mb(nbytes)}, above the {_mb(MAX_FILE_BYTES)} limit - not scanned"
        )
    return nbytes


def checked_zipfile(path):
    """Open an OOXML file as a zip after checking what it expands to.

    The central directory is inspected before any member is read, so a bomb
    is refused on its declared sizes rather than by being unpacked first. A
    zip can of course understate those, which is why the on-disk size is
    checked too and the ratio is capped: getting past this needs the archive
    to lie about its own contents, which is itself worth failing loudly on.
    """
    check_file_size(path)
    zf = zipfile.ZipFile(path)
    try:
        infos = zf.infolist()
        uncompressed = sum(i.file_size for i in infos)
        compressed = sum(i.compress_size for i in infos)

        if uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise LimitExceeded(
                f"archive expands to {_mb(uncompressed)}, above the "
                f"{_mb(MAX_UNCOMPRESSED_BYTES)} limit - not scanned"
            )

        # ignore tiny archives, where a high ratio is just efficient packing
        if compressed > 4096:
            ratio = uncompressed / compressed
            if ratio > MAX_COMPRESSION_RATIO:
                raise LimitExceeded(
                    f"archive expands {ratio:.0f}x ({_mb(compressed)} to "
                    f"{_mb(uncompressed)}), above the {MAX_COMPRESSION_RATIO}x "
                    f"limit - not scanned"
                )
    except Exception:
        zf.close()
        raise
    return zf
