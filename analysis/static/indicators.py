from typing import List
from analysis.static.schemas import (
    PEHeaderInfo,
    SectionInfo,
    ImportInfo,
    EntropyStats,
    StaticIndicator
)


def generate_static_indicators(
    headers: PEHeaderInfo,
    sections: List[SectionInfo],
    imports: ImportInfo,
    entropy: EntropyStats
) -> List[StaticIndicator]:
    """
    Derives rule-based static security indicators from extracted PE metadata.
    Indicators represent evidence/observed characteristics, NOT automatic proof of malware.
    """
    indicators: List[StaticIndicator] = []

    # 1. High Section Entropy Check (Potential Packer / Encryption)
    if entropy.high_entropy_sections_count > 0:
        indicators.append(StaticIndicator(
            indicator_code="HIGH_SECTION_ENTROPY",
            name="Packed/Encrypted Section Detected",
            category="Entropy Analysis",
            severity="MEDIUM",
            evidence=f"{entropy.high_entropy_sections_count} section(s) have entropy >= 7.0 (max entropy: {entropy.max})"
        ))

    # 2. Executable and Writable Section Check (Self-Modifying / RWX Code)
    rwx_sections = [s.name for s in sections if s.executable and s.writable]
    if rwx_sections:
        indicators.append(StaticIndicator(
            indicator_code="EXECUTABLE_AND_WRITABLE_SECTION",
            name="RWX (Executable & Writable) Section",
            category="PE Section Characteristics",
            severity="HIGH",
            evidence=f"Section(s) {', '.join(rwx_sections)} have both EXECUTE and WRITE permissions set."
        ))

    # 3. Custom / Unusual Section Name Check
    unusual_sections = [s.name for s in sections if s.is_suspicious_name]
    if unusual_sections:
        indicators.append(StaticIndicator(
            indicator_code="UNUSUAL_SECTION_NAME",
            name="Non-Standard PE Section Name",
            category="PE Structure",
            severity="LOW",
            evidence=f"Non-standard section name(s) observed: {', '.join(unusual_sections)}"
        ))

    # 4. Suspicious Win32 API Imports Check
    if imports.suspicious_apis:
        api_list = [f"{item['api']} ({item['category']})" for item in imports.suspicious_apis[:5]]
        indicators.append(StaticIndicator(
            indicator_code="SUSPICIOUS_IMPORT",
            name="Security-Sensitive API Import",
            category="Imports & Telemetry",
            severity="MEDIUM",
            evidence=f"Imported {len(imports.suspicious_apis)} sensitive API(s), including: {', '.join(api_list)}"
        ))

    # 5. Abnormal Section Count Check
    if headers.number_of_sections < 1 or headers.number_of_sections > 12:
        indicators.append(StaticIndicator(
            indicator_code="ABNORMAL_SECTION_COUNT",
            name="Abnormal Section Count",
            category="PE Structure",
            severity="LOW",
            evidence=f"PE binary contains {headers.number_of_sections} section(s) (typical range: 2-9)."
        ))

    # 6. Unusual Entry Point Check
    if headers.entry_point == 0 and not headers.is_dll:
        indicators.append(StaticIndicator(
            indicator_code="UNUSUAL_ENTRY_POINT",
            name="Zero Entry Point Address",
            category="Header Metadata",
            severity="MEDIUM",
            evidence="Executable entry point address is 0x00000000."
        ))

    # 7. Low / Zero Import Table Check
    if imports.dll_count == 0 and not headers.is_driver:
        indicators.append(StaticIndicator(
            indicator_code="ZERO_IMPORT_TABLE",
            name="Missing Import Table",
            category="Imports & Telemetry",
            severity="MEDIUM",
            evidence="Binary imports 0 DLLs, suggesting dynamic loading, packing, or raw shellcode."
        ))

    return indicators
