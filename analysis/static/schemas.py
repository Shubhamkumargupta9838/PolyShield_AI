from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class PEHeaderInfo(BaseModel):
    dos_header_valid: bool = True
    pe_signature_valid: bool = True
    machine_raw: int = 0
    architecture: str = "Unknown"
    number_of_sections: int = 0
    timestamp_raw: int = 0
    timestamp: Optional[str] = None
    characteristics_raw: int = 0
    entry_point: int = 0
    image_base: int = 0
    subsystem_raw: int = 0
    subsystem: str = "Unknown"
    dll_characteristics_raw: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    is_dll: bool = False
    is_driver: bool = False
    is_executable: bool = True


class SectionInfo(BaseModel):
    name: str
    virtual_size: int
    raw_size: int
    virtual_address: int
    raw_pointer: int
    characteristics_raw: int
    entropy: float
    executable: bool
    writable: bool
    readable: bool
    is_suspicious_name: bool = False


class ImportInfo(BaseModel):
    dll_count: int = 0
    api_count: int = 0
    dlls: List[str] = []
    apis: List[str] = []
    suspicious_apis: List[Dict[str, str]] = []  # {"api": "VirtualAlloc", "category": "Memory Allocation"}


class ResourceInfo(BaseModel):
    count: int = 0
    types: List[str] = []
    total_size: int = 0


class EntropyStats(BaseModel):
    max: float = 0.0
    min: float = 0.0
    mean: float = 0.0
    high_entropy_sections_count: int = 0  # Sections with entropy > threshold (7.0)


class StaticIndicator(BaseModel):
    indicator_code: str
    name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str


class FileMetadata(BaseModel):
    filename: str
    file_size: int
    sha256: str
    md5: str
    sha1: str


class StaticAnalysisResult(BaseModel):
    file: FileMetadata
    pe: PEHeaderInfo
    sections: List[SectionInfo]
    imports: ImportInfo
    resources: ResourceInfo
    entropy: EntropyStats
    indicators: List[StaticIndicator]
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)


class StaticFeatureVector(BaseModel):
    file_size: float
    number_of_sections: float
    dll_count: float
    api_count: float
    max_section_entropy: float
    min_section_entropy: float
    mean_section_entropy: float
    high_entropy_section_count: float
    executable_section_count: float
    writable_section_count: float
    rwx_section_count: float
    unusual_section_count: float
    resource_count: float
    suspicious_api_count: float
    static_indicator_count: float
    is_dll: float
    is_driver: float

    @classmethod
    def feature_names(cls) -> List[str]:
        return [
            "file_size",
            "number_of_sections",
            "dll_count",
            "api_count",
            "max_section_entropy",
            "min_section_entropy",
            "mean_section_entropy",
            "high_entropy_section_count",
            "executable_section_count",
            "writable_section_count",
            "rwx_section_count",
            "unusual_section_count",
            "resource_count",
            "suspicious_api_count",
            "static_indicator_count",
            "is_dll",
            "is_driver",
        ]

    def to_dict(self) -> Dict[str, float]:
        return self.model_dump()
