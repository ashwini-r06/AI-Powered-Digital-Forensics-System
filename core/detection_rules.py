"""Transparent heuristic detections; findings are leads, not proof."""
import pandas as pd

def run_detection_rules(frame: pd.DataFrame) -> pd.DataFrame:
    findings=[]
    if frame is None or frame.empty: return pd.DataFrame(columns=["rule_id","title","severity","category","description","source_ip","username","event_count","recommendation"])
    text_cols=[c for c in ["event_type","message","action","description","event"] if c in frame.columns]
    text=frame[text_cols].fillna("").astype(str).agg(" ".join,axis=1).str.lower() if text_cols else pd.Series([""]*len(frame),index=frame.index)
    if "username" in frame.columns and ("event_type" in frame.columns or text_cols):
        failed=text.str.contains(r"failed|failure|invalid password|authentication denied",regex=True,na=False)
        user=frame.loc[failed,"username"].fillna("unknown").astype(str)
        for name,count in user.value_counts().items():
            if count>=5:
                findings.append(dict(rule_id="AUTH-001",title="Repeated failed logins",severity="HIGH",category="Authentication",description=f"Observed {count} failed-login indicators for account {name}.",source_ip="",username=name,event_count=int(count),recommendation="Review source addresses and confirm whether the activity is expected."))
    if text.str.contains(r"port.?scan|syn scan|nmap",regex=True,na=False).any():
        subset=frame.loc[text.str.contains(r"port.?scan|syn scan|nmap",regex=True,na=False)]
        for _,row in subset.iterrows(): findings.append(dict(rule_id="NET-001",title="Possible port scan indicator",severity="MEDIUM",category="Network",description="Log text contains a port-scanning indicator.",source_ip=str(row.get("source_ip","")),username=str(row.get("username","")),event_count=1,recommendation="Correlate with firewall and network telemetry."))
    suspicious=text.str.contains(r"powershell.*-enc|encodedcommand|\bcurl\b.*\|.*sh|\bwget\b.*\|.*sh",regex=True,na=False)
    for _,row in frame.loc[suspicious].iterrows():
        findings.append(dict(rule_id="CMD-001",title="Suspicious command indicator",severity="HIGH",category="Execution",description="A command string matches a configured suspicious-command pattern.",source_ip=str(row.get("source_ip","")),username=str(row.get("username","")),event_count=1,recommendation="Preserve the event and review process lineage with an analyst."))
    return pd.DataFrame(findings,columns=["rule_id","title","severity","category","description","source_ip","username","event_count","recommendation"])
