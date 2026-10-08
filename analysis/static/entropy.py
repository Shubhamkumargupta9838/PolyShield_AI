import math
from typing import List, Dict, Any
from analysis.static.schemas import EntropyStats


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon Entropy of a byte array.
    Returns float value between 0.0000 (uniform/predictable) and 8.0000 (completely random/encrypted).
    Zero-division safe and handles empty bytes cleanly.
    """
    if not data:
        return 0.0

    length = len(data)
    if length == 0:
        return 0.0

    occurrence = [0] * 256
    for byte in data:
        occurrence[byte] += 1

    entropy = 0.0
    for count in occurrence:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return round(float(entropy), 4)


def calculate_entropy_stats(sections: List[Any], threshold: float = 7.0) -> EntropyStats:
    """
    Calculate aggregate entropy statistics across PE sections.
    """
    if not sections:
        return EntropyStats(max=0.0, min=0.0, mean=0.0, high_entropy_sections_count=0)

    entropies = [sec.entropy if hasattr(sec, 'entropy') else sec.get('entropy', 0.0) for sec in sections]

    if not entropies:
        return EntropyStats(max=0.0, min=0.0, mean=0.0, high_entropy_sections_count=0)

    max_entropy = max(entropies)
    min_entropy = min(entropies)
    mean_entropy = sum(entropies) / len(entropies)
    high_count = sum(1 for e in entropies if e >= threshold)

    return EntropyStats(
        max=round(max_entropy, 4),
        min=round(min_entropy, 4),
        mean=round(mean_entropy, 4),
        high_entropy_sections_count=high_count
    )
