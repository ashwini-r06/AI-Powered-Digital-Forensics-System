"""Correlate log events sharing common investigative identifiers."""
import pandas as pd

def correlate_events(dataframe: pd.DataFrame) -> pd.DataFrame:
    frame=dataframe.copy()
    frame["correlation_id"]=""
    frame["correlation_reason"]=""
    frame["correlation_status"]="UNRELATED"
    keys=[c for c in ("source_ip","username","host") if c in frame.columns]
    if not keys or frame.empty: return frame
    counts={}
    for col in keys:
        values=frame[col].fillna("").astype(str).str.strip()
        for value in values:
            if value and value.lower() not in {"unknown","nan","none",""}: counts[(col,value)]=counts.get((col,value),0)+1
    for idx,row in frame.iterrows():
        matched=[(col,str(row.get(col,"")).strip()) for col in keys if str(row.get(col," ")).strip() and counts.get((col,str(row.get(col," ")).strip()),0)>1]
        if matched:
            col,value=matched[0]
            frame.at[idx,"correlation_id"]=f"CORR-{col}-{value}"
            frame.at[idx,"correlation_reason"]=f"Shared {col}: {value}"
            frame.at[idx,"correlation_status"]="CORRELATED"
    return frame
