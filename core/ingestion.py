"""Validate CSV and JSON evidence uploads without modifying original bytes."""
import json
from io import BytesIO
from pathlib import Path
import pandas as pd
from config import MAX_UPLOAD_SIZE_BYTES, MAX_UPLOAD_ROWS, ALLOWED_UPLOAD_EXTENSIONS

RECOGNIZED_FIELDS = {"timestamp", "time", "@timestamp", "event", "event_type", "event_id", "source", "host", "hostname", "user", "username", "ip", "src_ip", "dst_ip", "source_ip", "destination_ip", "message", "action"}

def _parse_json(content: bytes) -> pd.DataFrame:
    try:
        payload=json.loads(content.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ValueError("JSON must use UTF-8 encoding.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}.") from exc
    if isinstance(payload,list): records=payload
    elif isinstance(payload,dict) and isinstance(payload.get("records"),list): records=payload["records"]
    elif isinstance(payload,dict) and isinstance(payload.get("events"),list): records=payload["events"]
    else: raise ValueError("JSON must contain an array of records or a 'records'/'events' list.")
    if not records: raise ValueError("The JSON file contains no records.")
    if len(records)>MAX_UPLOAD_ROWS: raise ValueError(f"Maximum supported rows: {MAX_UPLOAD_ROWS:,}.")
    if not all(isinstance(row,dict) for row in records): raise ValueError("Every JSON record must be an object with named fields.")
    return pd.json_normalize(records,sep=".")

def _parse_csv(content: bytes) -> pd.DataFrame:
    try:
        frame=pd.read_csv(BytesIO(content),encoding="utf-8-sig",nrows=MAX_UPLOAD_ROWS+1,on_bad_lines="error",low_memory=False)
    except UnicodeDecodeError as exc: raise ValueError("CSV must use UTF-8 encoding.") from exc
    except pd.errors.EmptyDataError as exc: raise ValueError("The CSV file is empty.") from exc
    except (pd.errors.ParserError,ValueError) as exc: raise ValueError(f"CSV parsing failed: {exc}") from exc
    if len(frame)>MAX_UPLOAD_ROWS: raise ValueError(f"Maximum supported rows: {MAX_UPLOAD_ROWS:,}.")
    if not len(frame.columns): raise ValueError("The CSV file has no columns.")
    columns=[str(c).strip() for c in frame.columns]
    if any(not c for c in columns): raise ValueError("The CSV contains an empty column name.")
    if len({c.casefold() for c in columns}) != len(columns): raise ValueError("The CSV contains duplicate column names.")
    frame.columns=columns
    if frame.empty: raise ValueError("The CSV contains headers but no data rows.")
    return frame

def validate_and_parse_file(filename: str, content: bytes) -> dict:
    """Return validation metadata and a dataframe for a CSV/JSON file."""
    safe_name=Path(filename).name
    ext=Path(safe_name).suffix.lower()
    result={"filename":safe_name,"valid":False,"errors":[],"warnings":[],"dataframe":None,"row_count":0,"columns":[],"file_size":len(content),"format":ext.lstrip(".")}
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        result["errors"].append("Unsupported format. Upload a .csv or .json file."); return result
    if not content:
        result["errors"].append("The uploaded file is empty."); return result
    if len(content)>MAX_UPLOAD_SIZE_BYTES:
        result["errors"].append(f"File exceeds the {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB size limit."); return result
    try: frame=_parse_csv(content) if ext==".csv" else _parse_json(content)
    except (ValueError,TypeError) as exc:
        result["errors"].append(str(exc)); return result
    if frame.empty:
        result["errors"].append("No usable records were found."); return result
    fields={str(c).strip().casefold() for c in frame.columns}
    if not fields.intersection(RECOGNIZED_FIELDS): result["warnings"].append("No commonly recognized log fields were found. Review the columns before investigation.")
    if frame.isna().all(axis=1).any(): result["warnings"].append("One or more records contain only missing values.")
    result.update(valid=True,dataframe=frame,row_count=len(frame),columns=list(frame.columns))
    return result
