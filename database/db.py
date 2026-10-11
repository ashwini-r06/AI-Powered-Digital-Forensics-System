"""Database access layer for CyberSentry AI (SQLite + SQLAlchemy)."""

from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import DATA_DIR
from database.models import (
    Base,
    InvestigationCase,
    EvidenceRecord,
    SecurityFinding,
    AuditEntry,
    IncidentRecord,
)

DATABASE_PATH = Path(DATA_DIR) / "cybersentry.db"
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

_engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(
    bind=_engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


def initialize_database() -> None:
    """Create all tables defined by database.models."""
    Base.metadata.create_all(bind=_engine)


def _as_dict(obj: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: getattr(obj, field, None) for field in fields}


CASE_FIELDS = (
    "id", "case_number", "title", "description", "status",
    "priority", "created_at", "updated_at",
)
EVIDENCE_FIELDS = (
    "id", "case_id", "filename", "sha256", "file_size",
    "evidence_status", "recorded_at",
)
FINDING_FIELDS = (
    "id", "case_id", "rule_id", "title", "severity", "category",
    "description", "source_ip", "username", "event_count", "status",
    "created_at",
)
AUDIT_FIELDS = ("id", "case_id", "action", "actor", "details", "created_at")
INCIDENT_FIELDS = (
    "id", "title", "severity", "description", "status",
    "response_actions", "created_at", "updated_at",
)


def create_case(
    title: str,
    description: str = "",
    priority: str = "MEDIUM",
) -> dict[str, Any]:
    """Create a case and return its fields."""
    clean_title = str(title or "").strip()
    if not clean_title:
        raise ValueError("Case title cannot be empty.")

    with SessionLocal() as session:
        case = InvestigationCase(
            case_number=f"CS-{uuid4().hex[:10].upper()}",
            title=clean_title,
            description=str(description or ""),
            status="OPEN",
            priority=str(priority or "MEDIUM").upper(),
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        return _as_dict(case, CASE_FIELDS)


def list_cases() -> list[dict[str, Any]]:
    """Return cases newest first."""
    with SessionLocal() as session:
        rows = (
            session.query(InvestigationCase)
            .order_by(InvestigationCase.id.desc())
            .all()
        )
        return [_as_dict(row, CASE_FIELDS) for row in rows]


def get_case_details(case_id: int) -> dict[str, Any] | None:
    """Return a case and its evidence, findings, and audit entries."""
    with SessionLocal() as session:
        case = session.get(InvestigationCase, int(case_id))
        if case is None:
            return None

        evidence = (
            session.query(EvidenceRecord)
            .filter(EvidenceRecord.case_id == case.id)
            .order_by(EvidenceRecord.id.desc())
            .all()
        )
        findings = (
            session.query(SecurityFinding)
            .filter(SecurityFinding.case_id == case.id)
            .order_by(SecurityFinding.id.desc())
            .all()
        )
        audit = (
            session.query(AuditEntry)
            .filter(AuditEntry.case_id == case.id)
            .order_by(AuditEntry.id.desc())
            .all()
        )
        return {
            "case": _as_dict(case, CASE_FIELDS),
            "evidence": [_as_dict(row, EVIDENCE_FIELDS) for row in evidence],
            "findings": [_as_dict(row, FINDING_FIELDS) for row in findings],
            "audit_entries": [_as_dict(row, AUDIT_FIELDS) for row in audit],
        }


def update_case_status(
    case_id: int,
    status: str,
) -> dict[str, Any] | None:
    """Update the status of a case."""
    allowed = {"OPEN", "IN_PROGRESS", "CLOSED"}
    new_status = str(status or "").strip().upper()
    if new_status not in allowed:
        raise ValueError(f"Status must be one of: {', '.join(sorted(allowed))}")

    with SessionLocal() as session:
        case = session.get(InvestigationCase, int(case_id))
        if case is None:
            return None
        case.status = new_status
        session.commit()
        session.refresh(case)
        return _as_dict(case, CASE_FIELDS)


def add_evidence(
    case_id: int,
    filename: str,
    sha256: str,
    file_size: int,
    evidence_status: str = "HASHED",
) -> dict[str, Any]:
    """Save evidence metadata against an existing case."""
    with SessionLocal() as session:
        case = session.get(InvestigationCase, int(case_id))
        if case is None:
            raise ValueError(f"Case {case_id} does not exist.")

        row = EvidenceRecord(
            case_id=case.id,
            filename=Path(str(filename)).name,
            sha256=str(sha256),
            file_size=max(0, int(file_size)),
            evidence_status=str(evidence_status or "HASHED"),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _as_dict(row, EVIDENCE_FIELDS)


def add_finding(
    case_id: int,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    source_ip: str = "",
    username: str = "",
    event_count: int = 0,
) -> dict[str, Any]:
    """Save a detection finding against an existing case."""
    with SessionLocal() as session:
        case = session.get(InvestigationCase, int(case_id))
        if case is None:
            raise ValueError(f"Case {case_id} does not exist.")

        row = SecurityFinding(
            case_id=case.id,
            rule_id=str(rule_id or "UNKNOWN"),
            title=str(title or "Untitled finding"),
            severity=str(severity or "MEDIUM").upper(),
            category=str(category or "GENERAL"),
            description=str(description or ""),
            source_ip=str(source_ip or ""),
            username=str(username or ""),
            event_count=max(0, int(event_count or 0)),
            status="OPEN",
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _as_dict(row, FINDING_FIELDS)


def add_audit_entry(
    case_id: int,
    action: str,
    actor: str = "analyst",
    details: str = "",
) -> dict[str, Any]:
    """Append an audit entry to a case."""
    with SessionLocal() as session:
        case = session.get(InvestigationCase, int(case_id))
        if case is None:
            raise ValueError(f"Case {case_id} does not exist.")

        row = AuditEntry(
            case_id=case.id,
            action=str(action),
            actor=str(actor or "analyst"),
            details=str(details or ""),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _as_dict(row, AUDIT_FIELDS)


def create_incident_record(
    title: str,
    severity: str = "MEDIUM",
    description: str = "",
) -> dict[str, Any]:
    """Create a persistent incident-response record."""
    clean_title = str(title or "").strip()
    if not clean_title:
        raise ValueError("Incident title cannot be empty.")

    with SessionLocal() as session:
        row = IncidentRecord(
            title=clean_title,
            severity=str(severity or "MEDIUM").upper(),
            description=str(description or ""),
            status="NEW",
            response_actions=[],
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _as_dict(row, INCIDENT_FIELDS)


def list_incident_records() -> list[dict[str, Any]]:
    """Return persistent incidents newest first."""
    with SessionLocal() as session:
        rows = (
            session.query(IncidentRecord)
            .order_by(IncidentRecord.id.desc())
            .all()
        )
        return [_as_dict(row, INCIDENT_FIELDS) for row in rows]


def update_incident_record(
    incident_id: int,
    status: str | None = None,
    action: str | None = None,
    details: str = "",
    actor: str = "analyst",
) -> dict[str, Any] | None:
    """Update incident status and/or append a response action."""
    allowed = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}

    with SessionLocal() as session:
        row = session.get(IncidentRecord, int(incident_id))
        if row is None:
            return None

        if status is not None:
            new_status = str(status).strip().upper()
            if new_status not in allowed:
                raise ValueError(
                    "Incident status must be one of: "
                    + ", ".join(sorted(allowed))
                )
            row.status = new_status

        if action:
            actions = list(row.response_actions or [])
            actions.append({
                "action": str(action),
                "details": str(details or ""),
                "actor": str(actor or "analyst"),
            })
            row.response_actions = actions

        session.commit()
        session.refresh(row)
        return _as_dict(row, INCIDENT_FIELDS)


initialize_database()
