"""Dynamic Sequence Explainer for PyTorch LSTM Model (Phase 12).

Uses Captum LayerIntegratedGradients to compute event-level attributions across dynamic telemetry sequences.
Excludes <PAD> tokens from displayed explanations, preserves <UNK> token visibility, and builds
temporal sequence timelines.
"""

import math
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import numpy as np

import torch
import torch.nn as nn
from captum.attr import LayerIntegratedGradients

from ml.data.dynamic_vocab import EventVocabulary, PAD_ID, UNK_ID
from ml.data.dynamic_dataset_builder import DynamicDatasetBuilder
from ml.models.lstm import DynamicLSTMModel, MODEL_VERSION
from ml.explainability.schemas import (
    DynamicExplanation,
    EventAttribution,
    DirectionEnum,
)

logger = logging.getLogger("polyshield.dynamic_explainer")


class DynamicSequenceExplainer:
    """Explainer for PyTorch DynamicLSTMModel using LayerIntegratedGradients."""

    def __init__(
        self,
        weights_path: str | Path = f"ml/artifacts/models/{MODEL_VERSION}.pt",
        meta_path: str | Path = f"ml/artifacts/models/{MODEL_VERSION}.json",
    ):
        self.weights_path = Path(weights_path)
        self.meta_path = Path(meta_path)
        self.model = DynamicLSTMModel.load_artifact(self.weights_path, self.meta_path)
        self.vocab = EventVocabulary()
        self.builder = DynamicDatasetBuilder(vocab=self.vocab)
        self.lig = LayerIntegratedGradients(self.model, self.model.embedding)

    def explain_telemetry(
        self,
        dynamic_result: Dict[str, Any],
        top_k: int = 5,
        n_steps: int = 50,
    ) -> DynamicExplanation:
        """Explains dynamic telemetry trace by computing LayerIntegratedGradients on embedding outputs.

        Args:
            dynamic_result: Normalized dynamic analysis result dictionary.
            top_k: Number of top contributing events to extract for summary.
            n_steps: Number of integration steps for Integrated Gradients.

        Returns:
            DynamicExplanation schema containing sequence length, unknown rate, event attributions, and timeline.
        """
        # 1. Encode telemetry into event sequence tensor
        sha256 = str(dynamic_result.get("sample_sha256") or dynamic_result.get("sha256") or "0" * 64)
        seq_obj = self.builder.convert_result_to_sequence(dynamic_result, sample_sha256=sha256)
        input_ids_np, stats = self.builder.encode_sequence(seq_obj)

        seq_len = int(stats.get("raw_length", 0))
        unk_rate = float(stats.get("unk_rate", 0.0))
        events_raw = getattr(seq_obj, "events", [])

        input_tensor = torch.from_numpy(input_ids_np).long().unsqueeze(0)  # (1, 256)

        # 2. Forward model prediction
        self.model.eval()
        with torch.no_grad():
            prob = float(self.model.predict_proba(input_tensor)[0])

        # 3. Compute LayerIntegratedGradients attributions on Embedding layer
        baseline_tensor = torch.full_like(input_tensor, PAD_ID)

        try:
            attributions_layer, delta = self.lig.attribute(
                input_tensor,
                baselines=baseline_tensor,
                n_steps=n_steps,
                return_convergence_delta=True,
            )
            attributions_seq = attributions_layer.sum(dim=-1).squeeze(0).detach().cpu().numpy()
        except Exception as e:
            logger.warning(f"Captum IntegratedGradients failed: {e}. Falling back to leave-one-out occlusion.")
            attributions_seq = self._occlusion_fallback(input_tensor, prob)

        # 4. Filter PAD tokens & construct EventAttribution items
        raw_attributions: List[Tuple[int, int, str, str, float]] = []

        for i in range(min(seq_len, len(input_ids_np))):
            token_id = int(input_ids_np[i])
            if token_id == PAD_ID:
                continue

            contrib = float(attributions_seq[i])
            if i < len(events_raw):
                evt = events_raw[i]
                rel_time = int(getattr(evt, "relative_time_ms", 0))
                evt_name = str(getattr(evt, "event_type", self.vocab.id_to_token.get(token_id, "<UNK>")))
                evt_cat = str(getattr(evt, "event_category", "behavioral"))
            else:
                rel_time = i * 10
                evt_name = self.vocab.id_to_token.get(token_id, "<UNK>")
                evt_cat = "behavioral"

            if token_id == UNK_ID and "<UNK>" not in evt_name:
                evt_name = f"<UNK> ({evt_name})"

            raw_attributions.append((i, rel_time, evt_name, evt_cat, contrib))

        # 5. Create timeline (ordered by sequence position / relative timestamp)
        timeline: List[EventAttribution] = []
        for i, rel_time, evt_name, evt_cat, contrib in raw_attributions:
            if contrib > 1e-4:
                direction = DirectionEnum.POSITIVE
            elif contrib < -1e-4:
                direction = DirectionEnum.NEGATIVE
            else:
                direction = DirectionEnum.NEUTRAL

            timeline.append(
                EventAttribution(
                    event_index=i,
                    relative_time_ms=rel_time,
                    event_type=evt_name,
                    event_category=evt_cat,
                    contribution=round(contrib, 4),
                    direction=direction,
                    rank=1,
                )
            )

        # 6. Rank attributions by absolute contribution magnitude descending
        sorted_indices = sorted(range(len(raw_attributions)), key=lambda idx: abs(raw_attributions[idx][4]), reverse=True)
        ranked_attributions: List[EventAttribution] = [None] * len(raw_attributions)

        for rank_pos, idx in enumerate(sorted_indices, start=1):
            i, rel_time, evt_name, evt_cat, contrib = raw_attributions[idx]
            if contrib > 1e-4:
                direction = DirectionEnum.POSITIVE
            elif contrib < -1e-4:
                direction = DirectionEnum.NEGATIVE
            else:
                direction = DirectionEnum.NEUTRAL

            ranked_item = EventAttribution(
                event_index=i,
                relative_time_ms=rel_time,
                event_type=evt_name,
                event_category=evt_cat,
                contribution=round(contrib, 4),
                direction=direction,
                rank=rank_pos,
            )
            ranked_attributions[idx] = ranked_item

        for idx in range(len(timeline)):
            timeline[idx].rank = ranked_attributions[idx].rank

        top_k_attributions = sorted(ranked_attributions, key=lambda item: item.rank)[:top_k]

        return DynamicExplanation(
            model_version=MODEL_VERSION,
            explainer_type="Captum_LayerIntegratedGradients",
            sequence_length=seq_len,
            unknown_event_rate=round(unk_rate, 4),
            model_output=round(prob, 4),
            attributions=ranked_attributions,
            top_k_attributions=top_k_attributions,
            temporal_timeline=timeline,
        )

    def _occlusion_fallback(self, input_tensor: torch.Tensor, base_prob: float) -> np.ndarray:
        """Fallback occlusion attribution: measures delta P(malware) when replacing each token with PAD."""
        seq_len = input_tensor.shape[1]
        attributions = np.zeros(seq_len, dtype=np.float32)

        for i in range(seq_len):
            if input_tensor[0, i] == PAD_ID:
                continue
            temp = input_tensor.clone()
            temp[0, i] = PAD_ID
            prob_without_i = float(self.model.predict_proba(temp)[0])
            attributions[i] = base_prob - prob_without_i

        return attributions
