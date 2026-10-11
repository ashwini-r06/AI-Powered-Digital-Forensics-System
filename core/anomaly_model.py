"""Isolation Forest anomaly scoring for small structured log datasets."""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import DictVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import make_pipeline
from config import ANOMALY_CONTAMINATION, ANOMALY_RANDOM_STATE, MINIMUM_ANOMALY_EVENTS

def detect_anomalies(dataframe: pd.DataFrame, contamination=ANOMALY_CONTAMINATION, random_state=ANOMALY_RANDOM_STATE) -> pd.DataFrame:
    frame=dataframe.copy()
    frame["anomaly_score"]=0.0
    frame["is_anomaly"]=False
    frame["anomaly_status"]="NOT_EVALUATED"
    if len(frame)<MINIMUM_ANOMALY_EVENTS:
        frame["anomaly_status"]="INSUFFICIENT_DATA"
        return frame
    safe_contamination=min(max(float(contamination),0.001),0.5)
    numeric=frame.select_dtypes(include="number").replace([float("inf"),float("-inf")],0).fillna(0)
    if numeric.empty:
        categorical=frame.select_dtypes(include=["object","category","bool"]).fillna("UNKNOWN").astype(str)
        if categorical.empty: categorical=pd.DataFrame({"event_index":range(len(frame))})
        encoded=pd.get_dummies(categorical, dummy_na=True)
        matrix=encoded.to_numpy(dtype=float)
    else:
        matrix=numeric.to_numpy(dtype=float)
    if matrix.shape[1]==0:
        matrix=pd.DataFrame({"event_index":range(len(frame))}).to_numpy(dtype=float)
    model=IsolationForest(contamination=safe_contamination,random_state=random_state,n_estimators=100)
    predictions=model.fit_predict(matrix)
    scores=-model.decision_function(matrix)
    frame["anomaly_score"]=scores
    frame["is_anomaly"]=predictions==-1
    frame["anomaly_status"]="EVALUATED"
    return frame
