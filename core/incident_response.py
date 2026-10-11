"""Simple in-memory incident workflow helpers retained for unit tests."""
from datetime import datetime, timezone
INCIDENT_STATUSES={"NEW","INVESTIGATING","CONTAINED","RESOLVED","CLOSED"}
def create_incident(title, severity="MEDIUM", description=""):
    return {"title":title,"severity":severity,"description":description,"status":"NEW","response_actions":[],"created_at":datetime.now(timezone.utc).isoformat()}
def transition_incident(incident,new_status):
    if new_status not in INCIDENT_STATUSES: raise ValueError(f"Unsupported incident status: {new_status}")
    incident["status"]=new_status; incident["updated_at"]=datetime.now(timezone.utc).isoformat(); return incident
def record_response_action(incident,action,details="",actor="analyst"):
    entry={"action":action,"details":details,"actor":actor,"recorded_at":datetime.now(timezone.utc).isoformat()}
    incident.setdefault("response_actions",[]).append(entry); return entry
