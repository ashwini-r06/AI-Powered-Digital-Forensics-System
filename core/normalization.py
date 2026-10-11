"""Normalize common log column names and timestamps."""
import pandas as pd
ALIASES={"timestamp":["timestamp","time","@timestamp","datetime","date_time","event_time"],"event_type":["event_type","event","action","event_name","type"],"host":["host","hostname","computer","device","machine"],"username":["username","user","account","user_name"],"source_ip":["source_ip","src_ip","srcip","client_ip","ip_src"],"destination_ip":["destination_ip","dst_ip","dstip","ip_dst","target_ip"],"message":["message","details","description","command","raw_message"]}
def normalize_logs(dataframe: pd.DataFrame) -> pd.DataFrame:
    frame=dataframe.copy()
    normalized={str(c).strip().lower().replace(" ","_"):c for c in frame.columns}
    rename={}
    for canonical,aliases in ALIASES.items():
        if canonical in normalized: continue
        for alias in aliases:
            if alias in normalized:
                rename[normalized[alias]]=canonical; break
    frame=frame.rename(columns=rename)
    if "timestamp" in frame.columns:
        frame["timestamp"]=pd.to_datetime(frame["timestamp"],errors="coerce",utc=True)
    if "event_type" in frame.columns:
        frame["event_type"]=frame["event_type"].fillna("UNKNOWN").astype(str).str.strip().str.upper()
    for col in ("host","username","source_ip","destination_ip","message"):
        if col in frame.columns: frame[col]=frame[col].fillna("").astype(str).str.strip()
    return frame
