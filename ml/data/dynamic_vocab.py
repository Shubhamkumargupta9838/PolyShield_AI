"""Deterministic Event Vocabulary for Dynamic Analysis Telemetry (Phase 10).

Provides stable, canonical mapping from event strings to token IDs.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

VOCAB_VERSION = "dynamic-v1.0"
PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
PAD_ID = 0
UNK_ID = 1

# Canonical list of predefined behavioral events in deterministic order
CANONICAL_EVENTS: List[str] = [
    PAD_TOKEN,
    UNK_TOKEN,
    # Process events
    "PROCESS_CREATE",
    "PROCESS_EXIT",
    "PROCESS_INJECT",
    "PROCESS_TERMINATE",
    # Network events
    "NETWORK_CONNECT",
    "NETWORK_DNS_QUERY",
    "NETWORK_DNS_RESPONSE",
    "NETWORK_BLOCKED",
    # Filesystem events
    "FILESYSTEM_CREATE",
    "FILESYSTEM_WRITE",
    "FILESYSTEM_READ",
    "FILESYSTEM_DELETE",
    "FILESYSTEM_RENAME",
    # Registry events
    "REGISTRY_CREATE_KEY",
    "REGISTRY_SET_VALUE",
    "REGISTRY_DELETE_KEY",
    "REGISTRY_OPEN_KEY",
    # API category events
    "API_PROCESS",
    "API_MEMORY",
    "API_FILE",
    "API_REGISTRY",
    "API_NETWORK",
    "API_CRYPTO",
    "API_SERVICE",
    "API_PERSISTENCE",
    "API_PRIVILEGE",
    "API_INJECTION",
]


class EventVocabulary:
    """Deterministic vocabulary mapping for dynamic behavioral sequence tokens."""

    def __init__(self, vocab_list: Optional[List[str]] = None, version: str = VOCAB_VERSION):
        self.version = version
        tokens = vocab_list if vocab_list is not None else list(CANONICAL_EVENTS)

        # Ensure PAD=0 and UNK=1
        if PAD_TOKEN not in tokens:
            tokens.insert(0, PAD_TOKEN)
        if UNK_TOKEN not in tokens:
            tokens.insert(1, UNK_TOKEN)

        self.token_to_id: Dict[str, int] = {token: idx for idx, token in enumerate(tokens)}
        self.id_to_token: Dict[int, str] = {idx: token for token, idx in self.token_to_id.items()}

    def __len__(self) -> int:
        return len(self.token_to_id)

    @classmethod
    def normalize_event_name(cls, raw_event: str) -> str:
        """Normalize raw event string variations into canonical uppercase representation."""
        if not raw_event:
            return UNK_TOKEN
        cleaned = raw_event.strip()
        # Handle snake_case or camelCase or lower_case conversion to UPPER_CASE
        # e.g. ProcessCreate -> PROCESS_CREATE, process_create -> PROCESS_CREATE
        if "_" in cleaned or cleaned.isupper():
            normalized = cleaned.upper()
        else:
            # Convert CamelCase to CAMEL_CASE
            import re
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", cleaned)
            normalized = re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).upper()

        return normalized

    def get_id(self, event_name: str) -> int:
        """Get token ID for event name, defaulting to UNK_ID if unrecognized."""
        norm_name = self.normalize_event_name(event_name)
        return self.token_to_id.get(norm_name, UNK_ID)

    def encode_events(self, event_names: List[str]) -> Tuple[List[int], int, float]:
        """Encode a list of raw event names into integer IDs.

        Returns:
            (token_ids, unknown_count, unknown_rate)
        """
        token_ids: List[int] = []
        unknown_count = 0
        total_count = len(event_names)

        for event in event_names:
            token_id = self.get_id(event)
            if token_id == UNK_ID:
                unknown_count += 1
            token_ids.append(token_id)

        unknown_rate = float(unknown_count / total_count) if total_count > 0 else 0.0
        return token_ids, unknown_count, unknown_rate

    def save_json(self, file_path: Path | str) -> None:
        """Save vocabulary mapping to JSON file."""
        data = {
            "vocab_version": self.version,
            "vocab_size": len(self.token_to_id),
            "pad_id": PAD_ID,
            "unk_id": UNK_ID,
            "token_to_id": self.token_to_id,
            "id_to_token": {str(k): v for k, v in self.id_to_token.items()},
        }
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_json(cls, file_path: Path | str) -> "EventVocabulary":
        """Load vocabulary from JSON file."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        token_to_id = data.get("token_to_id", {})
        # Sort by ID order
        sorted_tokens = [k for k, v in sorted(token_to_id.items(), key=lambda item: item[1])]
        return cls(vocab_list=sorted_tokens, version=data.get("vocab_version", VOCAB_VERSION))
