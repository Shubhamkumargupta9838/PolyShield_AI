from typing import Dict, Any, List


class FeaturePipeline:
    """Unified Feature Extraction & Normalization Pipeline for Static and Dynamic attributes."""
    def transform_static(self, raw_static: Dict[str, Any]) -> List[float]:
        return [0.0] * 32

    def transform_dynamic(self, raw_dynamic: Dict[str, Any]) -> List[float]:
        return [0.0] * 32
