import pefile
from typing import List
from analysis.static.schemas import SectionInfo
from analysis.static.entropy import calculate_shannon_entropy

STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".idata", ".edata",
    ".rsrc", ".reloc", ".pdata", ".tls", ".bss", ".cdata"
}


def parse_pe_sections(pe: pefile.PE) -> List[SectionInfo]:
    """Analyze PE sections for raw/virtual sizes, RWX characteristics, and Shannon entropy."""
    sections_info: List[SectionInfo] = []

    if not hasattr(pe, 'sections'):
        return sections_info

    for section in pe.sections:
        # Decode section name (strip trailing null bytes)
        try:
            name_raw = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        except Exception:
            name_raw = "UNKNOWN"

        name = name_raw if name_raw else "UNNAMED"

        virtual_size = getattr(section, 'Misc_VirtualSize', 0)
        raw_size = getattr(section, 'SizeOfRawData', 0)
        virtual_address = getattr(section, 'VirtualAddress', 0)
        raw_pointer = getattr(section, 'PointerToRawData', 0)
        characteristics = getattr(section, 'Characteristics', 0)

        # Characteristics flags
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000
        # IMAGE_SCN_MEM_READ    = 0x40000000
        # IMAGE_SCN_MEM_WRITE   = 0x80000000
        executable = bool(characteristics & 0x20000000)
        readable = bool(characteristics & 0x40000000)
        writable = bool(characteristics & 0x80000000)

        # Calculate section entropy safely
        section_bytes = section.get_data()
        entropy = calculate_shannon_entropy(section_bytes)

        is_suspicious_name = name.lower() not in STANDARD_SECTION_NAMES

        sections_info.append(SectionInfo(
            name=name,
            virtual_size=virtual_size,
            raw_size=raw_size,
            virtual_address=virtual_address,
            raw_pointer=raw_pointer,
            characteristics_raw=characteristics,
            entropy=entropy,
            executable=executable,
            writable=writable,
            readable=readable,
            is_suspicious_name=is_suspicious_name
        ))

    return sections_info
