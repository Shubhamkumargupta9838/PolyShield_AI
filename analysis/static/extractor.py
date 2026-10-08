import hashlib
import pefile
from typing import Dict, Any, Tuple
from analysis.static.schemas import (
    FileMetadata,
    StaticAnalysisResult,
    StaticFeatureVector
)
from analysis.static.headers import parse_pe_headers
from analysis.static.sections import parse_pe_sections
from analysis.static.imports import parse_pe_imports
from analysis.static.resources import parse_pe_resources
from analysis.static.entropy import calculate_entropy_stats
from analysis.static.indicators import generate_static_indicators


class StaticFeatureExtractor:
    """
    Master Static PE Feature Extractor.
    Operates strictly in-memory on raw file bytes without file execution or subprocess calls.
    """
    def extract_from_bytes(self, file_bytes: bytes, filename: str) -> StaticAnalysisResult:
        if not file_bytes:
            raise ValueError("File content is empty.")

        # Calculate cryptographic hashes
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()

        file_meta = FileMetadata(
            filename=filename,
            file_size=len(file_bytes),
            sha256=sha256,
            md5=md5,
            sha1=sha1
        )

        # Parse PE structure in memory safely
        try:
            pe = pefile.PE(data=file_bytes, fast_load=False)
        except Exception as e:
            raise ValueError(f"Invalid or corrupted Windows PE binary format: {str(e)}")

        try:
            headers = parse_pe_headers(pe)
            sections = parse_pe_sections(pe)
            imports = parse_pe_imports(pe)
            resources = parse_pe_resources(pe)
            entropy_stats = calculate_entropy_stats(sections, threshold=7.0)
            indicators = generate_static_indicators(headers, sections, imports, entropy_stats)
        finally:
            pe.close()

        return StaticAnalysisResult(
            file=file_meta,
            pe=headers,
            sections=sections,
            imports=imports,
            resources=resources,
            entropy=entropy_stats,
            indicators=indicators
        )

    def vectorize(self, result: StaticAnalysisResult) -> StaticFeatureVector:
        """
        Convert structured static analysis output into a deterministic ML feature vector.
        """
        rwx_count = sum(1 for s in result.sections if s.executable and s.writable)
        executable_count = sum(1 for s in result.sections if s.executable)
        writable_count = sum(1 for s in result.sections if s.writable)
        unusual_section_count = sum(1 for s in result.sections if s.is_suspicious_name)

        return StaticFeatureVector(
            file_size=float(result.file.file_size),
            number_of_sections=float(result.pe.number_of_sections),
            dll_count=float(result.imports.dll_count),
            api_count=float(result.imports.api_count),
            max_section_entropy=result.entropy.max,
            min_section_entropy=result.entropy.min,
            mean_section_entropy=result.entropy.mean,
            high_entropy_section_count=float(result.entropy.high_entropy_sections_count),
            executable_section_count=float(executable_count),
            writable_section_count=float(writable_count),
            rwx_section_count=float(rwx_count),
            unusual_section_count=float(unusual_section_count),
            resource_count=float(result.resources.count),
            suspicious_api_count=float(len(result.imports.suspicious_apis)),
            static_indicator_count=float(len(result.indicators)),
            is_dll=1.0 if result.pe.is_dll else 0.0,
            is_driver=1.0 if result.pe.is_driver else 0.0
        )
