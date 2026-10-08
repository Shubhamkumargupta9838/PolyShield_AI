from typing import List


def extract_api_sequence(api_calls: List[dict]) -> List[str]:
    """Extract ordered sequence of API function names from normalized call traces."""
    return [call.get("api", "") for call in api_calls if "api" in call]
