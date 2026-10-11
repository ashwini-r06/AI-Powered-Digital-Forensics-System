import pandas as pd
from core.normalization import normalize_logs

def test_aliases_normalize():
    result=normalize_logs(pd.DataFrame({"user":["alice"],"src_ip":["192.0.2.1"]}))
    assert "username" in result.columns and "source_ip" in result.columns
