"""Build chronological event timelines and summary statistics."""
import pandas as pd

def build_timeline(dataframe: pd.DataFrame) -> pd.DataFrame:
    frame=dataframe.copy()
    if "timestamp" in frame.columns:
        frame["timeline_time_utc"]=pd.to_datetime(frame["timestamp"],errors="coerce",utc=True)
        frame=frame.sort_values("timeline_time_utc",na_position="last")
    else:
        frame["timeline_time_utc"]=pd.NaT
    return frame.reset_index(drop=True)

def summarize_timeline(dataframe: pd.DataFrame) -> dict:
    total=len(dataframe) if dataframe is not None else 0
    if dataframe is None or dataframe.empty or "timeline_time_utc" not in dataframe.columns:
        return {"total_events":total,"timestamped_events":0,"events_without_valid_timestamp":total,"start_time_utc":None,"end_time_utc":None}
    times=pd.to_datetime(dataframe["timeline_time_utc"],errors="coerce",utc=True).dropna()
    return {"total_events":total,"timestamped_events":int(len(times)),"events_without_valid_timestamp":int(total-len(times)),"start_time_utc":times.min().isoformat() if len(times) else None,"end_time_utc":times.max().isoformat() if len(times) else None}
