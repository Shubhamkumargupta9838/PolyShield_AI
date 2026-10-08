import pytest
import numpy as np
import pandas as pd
from ml.data.constants import FEATURE_NAMES
from ml.models.random_forest import RandomForestBaseline
from ml.models.xgboost_model import XGBoostBaseline, compute_scale_pos_weight


@pytest.fixture
def synthetic_data():
    np.random.seed(42)
    X = pd.DataFrame(np.random.rand(20, 17), columns=FEATURE_NAMES)
    y = pd.Series([0] * 10 + [1] * 10)
    return X, y


def test_random_forest_baseline_fit_predict(synthetic_data):
    X, y = synthetic_data
    rf = RandomForestBaseline(n_estimators=10, random_state=42)
    
    assert not rf.is_fitted
    with pytest.raises(RuntimeError):
        rf.predict_proba(X)

    rf.fit(X, y)
    assert rf.is_fitted

    probas = rf.predict_proba(X)
    assert probas.shape == (20,)
    assert (probas >= 0.0).all() and (probas <= 1.0).all()

    preds = rf.predict(X, threshold=0.5)
    assert preds.shape == (20,)
    assert set(preds).issubset({0, 1})

    imp_df = rf.get_feature_importances()
    assert len(imp_df) == 17
    assert list(imp_df.columns) == ["feature", "importance", "rank"]
    assert set(imp_df["feature"]) == set(FEATURE_NAMES)


def test_xgboost_baseline_fit_predict(synthetic_data):
    X, y = synthetic_data
    xgb = XGBoostBaseline(n_estimators=10, max_depth=3, random_state=42)
    
    assert not xgb.is_fitted
    with pytest.raises(RuntimeError):
        xgb.predict_proba(X)

    xgb.fit(X, y)
    assert xgb.is_fitted

    probas = xgb.predict_proba(X)
    assert probas.shape == (20,)
    assert (probas >= 0.0).all() and (probas <= 1.0).all()

    preds = xgb.predict(X, threshold=0.5)
    assert preds.shape == (20,)
    assert set(preds).issubset({0, 1})

    imp_df = xgb.get_feature_importances()
    assert len(imp_df) == 17
    assert list(imp_df.columns) == ["feature", "importance", "rank"]
    assert set(imp_df["feature"]) == set(FEATURE_NAMES)


def test_compute_scale_pos_weight():
    # 3 benign (0), 5 malware (1) -> 3 / 5 = 0.6
    y_train = pd.Series([0, 0, 0, 1, 1, 1, 1, 1])
    assert compute_scale_pos_weight(y_train) == 0.6

    # Edge cases
    y_all_benign = pd.Series([0, 0, 0])
    assert compute_scale_pos_weight(y_all_benign) == 1.0

    y_all_malware = pd.Series([1, 1, 1])
    assert compute_scale_pos_weight(y_all_malware) == 1.0
