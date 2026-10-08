import pefile
from typing import List, Set
from analysis.static.schemas import ResourceInfo

RESOURCE_TYPE_MAP = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    24: "RT_MANIFEST"
}


def parse_pe_resources(pe: pefile.PE) -> ResourceInfo:
    """Extract safe metadata about PE resources without executing embedded payloads."""
    count = 0
    resource_types: Set[str] = set()
    total_size = 0

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_id = getattr(resource_type, 'id', None)
                if type_id is not None:
                    type_str = RESOURCE_TYPE_MAP.get(type_id, f"CUSTOM_TYPE_{type_id}")
                elif getattr(resource_type, 'name', None) is not None:
                    type_str = str(resource_type.name)
                else:
                    type_str = "UNKNOWN_TYPE"

                resource_types.add(type_str)

                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                count += 1
                                if hasattr(resource_lang, 'data'):
                                    size = getattr(resource_lang.data.struct, 'Size', 0)
                                    total_size += size
                        else:
                            count += 1
        except Exception:
            pass

    return ResourceInfo(
        count=count,
        types=sorted(list(resource_types)),
        total_size=total_size
    )
