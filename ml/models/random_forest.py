import numpy as np
import pandas as pd
from typing import List, Dict, Union, Any, Optional
from sklearn.ensemble import RandomForestClassifier
from ml.data.constants import FEATURE_NAMES


class RandomForestBaseline:
    """
    Random Forest Baseline Classifier for PolyShield AI static PE features.
    """

    def __init__(
        self,
        n_estimators: int = 300,
        random_state: int = 42,
        class_weight: str = "balanced",
        max_depth: Optional[int] = None,
        n_jobs: int = -1,
    ):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.class_weight = class_weight
        self.max_depth = max_depth
        self.n_jobs = n_jobs

        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            class_weight=self.class_weight,
            max_depth=self.max_depth,
            n_jobs=self.n_jobs,
        )
        self.is_fitted = False

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Union[pd.Series, np.ndarray]) -> "RandomForestBaseline":
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict_proba(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")
        probas = self.model.predict_proba(X)
        if probas.ndim == 2 and probas.shape[1] == 2:
            return probas[:, 1]
        return probas

    def predict(self, X: Union[pd.DataFrame, np.ndarray], threshold: float = 0.5) -> np.ndarray:
        probas = self.predict_proba(X)
        return (probas >= threshold).astype(int)

    def get_feature_importances(self, feature_names: List[str] = FEATURE_NAMES) -> pd.DataFrame:
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")
        importances = self.model.feature_importances_
        df_imp = pd.DataFrame({
            "feature": feature_names,
            "importance": importances
        }).sort_values(by="importance", ascending=False).reset_index(drop=True)
        df_imp["rank"] = range(1, len(df_imp) + 1)
        return df_imp

    def get_params(self) -> Dict[str, Any]:
        return {
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "class_weight": self.class_weight,
            "max_depth": self.max_depth,
            "n_jobs": self.n_jobs,
        }
