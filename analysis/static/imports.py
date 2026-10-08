import pefile
from typing import Dict, List, Set, Tuple
from analysis.static.schemas import ImportInfo

# Centralized Suspicious Win32 API Catalog
SUSPICIOUS_API_CATEGORIES: Dict[str, str] = {
    # Process Manipulation & Injection
    "VirtualAllocEx": "Process Injection / Memory Allocation",
    "WriteProcessMemory": "Process Injection / Memory Modification",
    "CreateRemoteThread": "Process Injection / Remote Execution",
    "QueueUserAPC": "Process Injection / APC Injection",
    "NtMapViewOfSection": "Process Injection / Process Hollowing",
    "RtlCreateUserThread": "Process Injection / Remote Threading",
    "OpenProcess": "Process Manipulation",
    "CreateProcessA": "Process Spawning",
    "CreateProcessW": "Process Spawning",

    # Memory Allocation & Protection
    "VirtualAlloc": "Memory Allocation",
    "VirtualProtect": "Memory Protection Change",
    "VirtualProtectEx": "Process Injection / Memory Protection",

    # Registry Modification / Persistence
    "RegSetValueExA": "Registry Modification / Persistence",
    "RegSetValueExW": "Registry Modification / Persistence",
    "RegCreateKeyExA": "Registry Key Creation",
    "RegCreateKeyExW": "Registry Key Creation",

    # Network Telemetry
    "InternetOpenA": "Network Telemetry",
    "InternetOpenW": "Network Telemetry",
    "HttpSendRequestA": "Network Telemetry / C2",
    "HttpSendRequestW": "Network Telemetry / C2",
    "URLDownloadToFileA": "Payload Downloading",
    "URLDownloadToFileW": "Payload Downloading",
    "WSAStartup": "Sockets Network Init",
    "socket": "Sockets Network Connection",
    "connect": "Sockets Network Connection",

    # Dynamic API Resolution & Evasion
    "LoadLibraryA": "Dynamic API Resolution",
    "LoadLibraryW": "Dynamic API Resolution",
    "GetProcAddress": "Dynamic API Resolution",
    "LdrLoadDll": "Dynamic API Resolution",
    "IsDebuggerPresent": "Anti-Debugging",
    "CheckRemoteDebuggerPresent": "Anti-Debugging",
    "NtQueryInformationProcess": "Anti-Debugging / Evasion"
}


def parse_pe_imports(pe: pefile.PE) -> ImportInfo:
    """Extract imported DLLs, function symbols, and tag security-relevant Win32 APIs."""
    dll_names: Set[str] = set()
    api_names: List[str] = []
    suspicious_apis: List[Dict[str, str]] = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8', errors='replace').lower()
            except Exception:
                dll_name = "unknown_dll"

            dll_names.add(dll_name)

            for imp in entry.imports:
                if imp.name:
                    try:
                        api_name = imp.name.decode('utf-8', errors='replace')
                    except Exception:
                        api_name = f"ord_{imp.ordinal}"
                else:
                    api_name = f"ord_{imp.ordinal}"

                api_names.append(api_name)

                # Check if API is in suspicious catalog
                if api_name in SUSPICIOUS_API_CATEGORIES:
                    suspicious_apis.append({
                        "api": api_name,
                        "category": SUSPICIOUS_API_CATEGORIES[api_name],
                        "dll": dll_name
                    })

    return ImportInfo(
        dll_count=len(dll_names),
        api_count=len(api_names),
        dlls=sorted(list(dll_names)),
        apis=api_names,
        suspicious_apis=suspicious_apis
    )
