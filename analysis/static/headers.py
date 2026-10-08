import pefile
from datetime import datetime, timezone
from typing import Dict, Any
from analysis.static.schemas import PEHeaderInfo

MACHINE_MAP = {
    0x014c: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x0200: "IA-64 (Itanium)",
    0x01c0: "ARM (Little Endian)",
    0xaa64: "ARM64 (Little Endian)",
}

SUBSYSTEM_MAP = {
    1: "Native / Driver",
    2: "Windows GUI",
    3: "Windows CUI (Console)",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
}


def parse_pe_headers(pe: pefile.PE) -> PEHeaderInfo:
    """Extract PE headers, architecture, entry point, and optional header attributes."""
    dos_valid = hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER.e_magic == 0x5A4D
    pe_valid = hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS.Signature == 0x4550

    machine_code = getattr(pe.FILE_HEADER, 'Machine', 0)
    architecture = MACHINE_MAP.get(machine_code, f"Unknown (0x{machine_code:04x})")

    num_sections = getattr(pe.FILE_HEADER, 'NumberOfSections', 0)
    timestamp_raw = getattr(pe.FILE_HEADER, 'TimeDateStamp', 0)
    try:
        dt = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc)
        timestamp_str = dt.isoformat()
    except Exception:
        timestamp_str = "Invalid/Malformed Timestamp"

    characteristics = getattr(pe.FILE_HEADER, 'Characteristics', 0)

    # Flags check
    is_dll = bool(characteristics & 0x2000)
    is_executable = bool(characteristics & 0x0002)

    entry_point = 0
    image_base = 0
    subsystem_code = 0
    subsystem_str = "Unknown"
    dll_characteristics = 0
    size_of_image = 0
    size_of_headers = 0

    if hasattr(pe, 'OPTIONAL_HEADER'):
        opt = pe.OPTIONAL_HEADER
        entry_point = getattr(opt, 'AddressOfEntryPoint', 0)
        image_base = getattr(opt, 'ImageBase', 0)
        subsystem_code = getattr(opt, 'Subsystem', 0)
        subsystem_str = SUBSYSTEM_MAP.get(subsystem_code, f"Unknown ({subsystem_code})")
        dll_characteristics = getattr(opt, 'DllCharacteristics', 0)
        size_of_image = getattr(opt, 'SizeOfImage', 0)
        size_of_headers = getattr(opt, 'SizeOfHeaders', 0)

    is_driver = (subsystem_code == 1)

    return PEHeaderInfo(
        dos_header_valid=dos_valid,
        pe_signature_valid=pe_valid,
        machine_raw=machine_code,
        architecture=architecture,
        number_of_sections=num_sections,
        timestamp_raw=timestamp_raw,
        timestamp=timestamp_str,
        characteristics_raw=characteristics,
        entry_point=entry_point,
        image_base=image_base,
        subsystem_raw=subsystem_code,
        subsystem=subsystem_str,
        dll_characteristics_raw=dll_characteristics,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        is_dll=is_dll,
        is_driver=is_driver,
        is_executable=is_executable
    )
