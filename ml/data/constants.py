from typing import List, Dict
from analysis.static.schemas import StaticFeatureVector

# Canonical ordered list of 17 static ML features (static-v1)
FEATURE_NAMES: List[str] = StaticFeatureVector.feature_names()

assert len(FEATURE_NAMES) == 17, "FEATURE_NAMES must contain exactly 17 features."
assert len(set(FEATURE_NAMES)) == 17, "FEATURE_NAMES must be unique."

# Supervised Target Mapping
LABEL_MAPPING: Dict[int, str] = {
    0: "benign",
    1: "malware"
}

# Versions
FEATURE_SCHEMA_VERSION: str = "static-v1"
DEFAULT_DATASET_VERSION: str = "v1.0"
