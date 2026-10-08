import numpy as np
import pandas as pd
from typing import List, Dict, Union, Any, Optional
from xgboost import XGBClassifier
from ml.data.constants import FEATURE_NAMES


def compute_scale_pos_weight(y_train: Union[pd.Series, np.ndarray]) -> float:
    """
    Computes scale_pos_weight = num_benign / num_malware strictly from training labels.
    Formula: scale_pos_weight = count(y == 0) / count(y == 1).
    Handles zero denominator/numerator edge cases safely.
    """
    y_arr = np.asarray(y_train)
    num_benign = int(np.sum(y_arr == 0))
    num_malware = int(np.sum(y_arr == 1))
    if num_malware == 0 or num_benign == 0:
        return 1.0
    return round(float(num_benign / num_malware), 4)


class XGBoostBaseline:
    """
    XGBoost Baseline Classifier for PolyShield AI static PE features.
    """

    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        scale_pos_weight: float = 1.0,
        random_state: int = 42,
        n_jobs: int = 1,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.subsample = subsample
        self.colsample_bytree = colsample_bytree
        self.scale_pos_weight = scale_pos_weight
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.model = XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            subsample=self.subsample,
            colsample_bytree=self.colsample_bytree,
            scale_pos_weight=self.scale_pos_weight,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            eval_metric="logloss",
        )
        self.is_fitted = False

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Union[pd.Series, np.ndarray]) -> "XGBoostBaseline":
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
            "max_depth": self.max_depth,
            "learning_rate": self.learning_rate,
            "subsample": self.subsample,
            "colsample_bytree": self.colsample_bytree,
            "scale_pos_weight": self.scale_pos_weight,
            "random_state": self.random_state,
            "n_jobs": self.n_jobs,
        }
