import json
from core.ingestion import validate_and_parse_file

def test_valid_csv():
    result=validate_and_parse_file("logs.csv",b"timestamp,event_type\n2026-01-01,LOGIN\n")
    assert result["valid"] is True
    assert result["row_count"]==1

def test_invalid_extension():
    result=validate_and_parse_file("logs.exe",b"hello")
    assert result["valid"] is False

def test_valid_json_records():
    result=validate_and_parse_file("logs.json",json.dumps([{"event":"login"}]).encode())
    assert result["valid"] is True
    assert result["row_count"]==1
