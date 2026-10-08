"""Centralized Safe Synthetic PE Binary Fixtures (Phase 14).

Provides safe in-memory synthetic PE byte streams for unit, integration, and performance testing.
All fixtures are non-executable engineering data structures. Zero host execution.
"""

import struct
import os


def create_minimal_pe_bytes() -> bytes:
    """Programmatically builds a safe, valid 1024-byte benign PE binary in memory."""
    pe_offset = 0x80
    dos_header = bytearray(pe_offset)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, pe_offset)

    nt_headers = bytearray()
    nt_headers += b"PE\x00\x00"

    # File Header (20 bytes)
    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: x86
        1,       # Num sections
        0x60000000, # Timestamp
        0, 0,    # Symbols
        224,     # Size of optional header
        0x0102   # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    nt_headers += file_header

    # Optional Header (224 bytes)
    opt_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B, 14, 0, 0x200, 0, 0,
        0x1000, 0x1000, 0x2000, 0x00400000, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0,
        0, 0x3000, 0x200, 0, 2, 0x8140,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16
    )
    opt_header += b"\x00" * 128
    nt_headers += opt_header

    # Section Header (40 bytes)
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00", 0x500, 0x1000, 0x200, 0x200,
        0, 0, 0, 0, 0x60000020  # EXECUTE | READ | CODE
    )

    full_pe = dos_header + nt_headers + sec_header
    if len(full_pe) < 0x200:
        full_pe += b"\x00" * (0x200 - len(full_pe))

    # Pad section payload
    full_pe += b"\x90" * 0x200
    return bytes(full_pe)


def create_dll_pe_bytes() -> bytes:
    """Creates a valid synthetic PE DLL binary byte stream."""
    pe_bytes = bytearray(create_minimal_pe_bytes())
    # Modify characteristics in COFF header (offset 0x80 + 4 + 18 = 0x96)
    # Set IMAGE_FILE_DLL (0x2000)
    orig_char = struct.unpack_from("<H", pe_bytes, 0x96)[0]
    struct.pack_into("<H", pe_bytes, 0x96, orig_char | 0x2000)
    return bytes(pe_bytes)


def create_rwx_pe_bytes() -> bytes:
    """Creates a synthetic PE binary containing an RWX section."""
    pe_bytes = bytearray(create_minimal_pe_bytes())
    # RWX section flags: 0xE0000020 (CODE | EXECUTE | READ | WRITE)
    # Section header flags offset is 0x80 + 4 + 20 + 224 + 36 = 0x1A4
    struct.pack_into("<I", pe_bytes, 0x1A4, 0xE0000020)
    return bytes(pe_bytes)


def create_high_entropy_pe_bytes() -> bytes:
    """Creates a synthetic PE binary containing high-entropy pseudo-random section data."""
    base_pe = create_minimal_pe_bytes()
    random_payload = os.urandom(1024)
    return base_pe + random_payload


def create_truncated_pe_bytes() -> bytes:
    """Creates a truncated/corrupted 20-byte PE byte stream."""
    return b"MZ" + b"\x90\x00" * 9


def create_non_pe_bytes() -> bytes:
    """Creates non-PE random text file bytes."""
    return b"THIS_IS_NOT_A_PE_FILE_DATA_STRUCTURE_PLAIN_TEXT_1234567890"
