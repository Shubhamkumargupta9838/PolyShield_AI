import pytest
import struct
import pefile
from analysis.static.entropy import calculate_shannon_entropy, calculate_entropy_stats
from analysis.static.extractor import StaticFeatureExtractor
from analysis.static.schemas import StaticAnalysisResult, StaticFeatureVector


def build_minimal_pe_bytes() -> bytes:
    """
    Programmatically builds a safe 1024-byte benign PE file in memory.
    Never contains executable instructions or real malware code.
    """
    pe_offset = 0x80
    dos_header = bytearray(pe_offset)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, pe_offset)

    nt_headers = bytearray()
    nt_headers += b'PE\x00\x00'  # Signature

    # File Header (20 bytes)
    machine = 0x014c  # x86
    num_sections = 1
    timestamp = 0x60000000
    pointer_symbol_table = 0
    num_symbols = 0
    size_opt_header = 224
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE

    file_header = struct.pack(
        '<HHIIIHH',
        machine,
        num_sections,
        timestamp,
        pointer_symbol_table,
        num_symbols,
        size_opt_header,
        characteristics
    )
    nt_headers += file_header

    # Optional Header (224 bytes)
    magic = 0x010b  # PE32
    major_linker = 14
    minor_linker = 0
    size_code = 0x200
    size_init_data = 0
    size_uninit_data = 0
    entry_point = 0x1000
    base_code = 0x1000
    base_data = 0x2000
    image_base = 0x00400000
    section_alignment = 0x1000
    file_alignment = 0x200
    major_os = 6
    minor_os = 0
    major_image = 0
    minor_image = 0
    major_subsys = 6
    minor_subsys = 0
    win32_version = 0
    size_image = 0x3000
    size_headers = 0x200
    checksum = 0
    subsystem = 2  # Windows GUI
    dll_characteristics = 0x8140
    size_stack_reserve = 0x100000
    size_stack_commit = 0x1000
    size_heap_reserve = 0x100000
    size_heap_commit = 0x1000
    loader_flags = 0
    num_rva_and_sizes = 16

    opt_header = struct.pack(
        '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
        magic, major_linker, minor_linker, size_code, size_init_data, size_uninit_data,
        entry_point, base_code, base_data, image_base, section_alignment, file_alignment,
        major_os, minor_os, major_image, minor_image, major_subsys, minor_subsys,
        win32_version, size_image, size_headers, checksum, subsystem, dll_characteristics,
        size_stack_reserve, size_stack_commit, size_heap_reserve, size_heap_commit,
        loader_flags, num_rva_and_sizes
    )
    # Add Data Directories (16 * 8 = 128 bytes)
    opt_header += b'\x00' * 128
    nt_headers += opt_header

    # Section Header (40 bytes)
    sec_name = b'.text\x00\x00\x00'
    sec_vsize = 0x500
    sec_vaddr = 0x1000
    sec_rsize = 0x200
    sec_rptr = 0x200
    sec_reloc = 0
    sec_lineno = 0
    sec_nreloc = 0
    sec_nlineno = 0
    sec_flags = 0x60000020  # EXECUTE | READ | CODE

    sec_header = struct.pack(
        '<8sIIIIIIHHI',
        sec_name, sec_vsize, sec_vaddr, sec_rsize, sec_rptr,
        sec_reloc, sec_lineno, sec_nreloc, sec_nlineno, sec_flags
    )

    full_pe = dos_header + nt_headers + sec_header
    # Pad up to 0x200 headers
    if len(full_pe) < 0x200:
        full_pe += b'\x00' * (0x200 - len(full_pe))

    # Add section raw data at 0x200 (512 bytes)
    section_data = b'\x90' * 0x200  # NOP instructions
    full_pe += section_data

    return bytes(full_pe)


# ------------------- ENTROPY TESTS ------------------- #
def test_entropy_empty_bytes():
    assert calculate_shannon_entropy(b'') == 0.0


def test_entropy_uniform_bytes():
    # 256 bytes with identical value 'A' has entropy 0.0
    data = b'A' * 256
    assert calculate_shannon_entropy(data) == 0.0


def test_entropy_random_looking_bytes():
    # 256 unique bytes 0..255 has maximum entropy 8.0
    data = bytes(range(256))
    assert calculate_shannon_entropy(data) == 8.0


def test_entropy_stats():
    class DummySection:
        def __init__(self, e):
            self.entropy = e

    sections = [DummySection(2.5), DummySection(7.2), DummySection(7.8)]
    stats = calculate_entropy_stats(sections, threshold=7.0)
    assert stats.max == 7.8
    assert stats.min == 2.5
    assert stats.high_entropy_sections_count == 2


# ------------------- PE EXTRACTION TESTS ------------------- #
def test_static_feature_extractor_valid_pe():
    pe_bytes = build_minimal_pe_bytes()
    extractor = StaticFeatureExtractor()

    result = extractor.extract_from_bytes(pe_bytes, "test_benign.exe")

    assert result.file.filename == "test_benign.exe"
    assert result.file.file_size == len(pe_bytes)
    assert len(result.file.sha256) == 64

    # PE headers check
    assert result.pe.dos_header_valid is True
    assert result.pe.pe_signature_valid is True
    assert result.pe.architecture == "x86 (32-bit)"
    assert result.pe.number_of_sections == 1
    assert result.pe.entry_point == 0x1000

    # Section check
    assert len(result.sections) == 1
    assert result.sections[0].name == ".text"
    assert result.sections[0].executable is True

    # Feature vector check
    vec = extractor.vectorize(result)
    assert isinstance(vec, StaticFeatureVector)
    d = vec.to_dict()
    assert d["file_size"] == float(len(pe_bytes))
    assert d["number_of_sections"] == 1.0


def test_static_feature_extractor_invalid_pe():
    extractor = StaticFeatureExtractor()
    invalid_bytes = b"THIS IS NOT A VALID PE FILE HEADER"

    with pytest.raises(ValueError, match="Invalid or corrupted Windows PE binary"):
        extractor.extract_from_bytes(invalid_bytes, "invalid.txt")


def test_static_feature_extractor_empty_bytes():
    extractor = StaticFeatureExtractor()
    with pytest.raises(ValueError, match="File content is empty"):
        extractor.extract_from_bytes(b"", "empty.exe")
