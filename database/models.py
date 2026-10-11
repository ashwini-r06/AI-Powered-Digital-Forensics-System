"""SQLAlchemy models for CyberSentry AI."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, relationship
Base=declarative_base()
def utc_now(): return datetime.now(timezone.utc)
class InvestigationCase(Base):
    __tablename__="investigation_cases"
    id=Column(Integer,primary_key=True)
    case_number=Column(String(40),unique=True,nullable=False,index=True)
    title=Column(String(250),nullable=False)
    description=Column(Text,default="")
    status=Column(String(30),nullable=False,default="OPEN")
    priority=Column(String(20),nullable=False,default="MEDIUM")
    created_at=Column(DateTime(timezone=True),default=utc_now,nullable=False)
    updated_at=Column(DateTime(timezone=True),default=utc_now,onupdate=utc_now,nullable=False)
    evidence=relationship("EvidenceRecord",back_populates="case",cascade="all, delete-orphan")
    findings=relationship("SecurityFinding",back_populates="case",cascade="all, delete-orphan")
    audit_entries=relationship("AuditEntry",back_populates="case",cascade="all, delete-orphan")
class EvidenceRecord(Base):
    __tablename__="evidence_records"
    id=Column(Integer,primary_key=True)
    case_id=Column(Integer,ForeignKey("investigation_cases.id"),nullable=False,index=True)
    filename=Column(String(255),nullable=False)
    sha256=Column(String(64),nullable=False)
    file_size=Column(Integer,nullable=False,default=0)
    evidence_status=Column(String(30),nullable=False,default="HASHED")
    recorded_at=Column(DateTime(timezone=True),default=utc_now,nullable=False)
    case=relationship("InvestigationCase",back_populates="evidence")
class SecurityFinding(Base):
    __tablename__="security_findings"
    id=Column(Integer,primary_key=True)
    case_id=Column(Integer,ForeignKey("investigation_cases.id"),nullable=False,index=True)
    rule_id=Column(String(80),nullable=False)
    title=Column(String(250),nullable=False)
    severity=Column(String(20),nullable=False,default="MEDIUM")
    category=Column(String(100),nullable=False,default="GENERAL")
    description=Column(Text,default="")
    source_ip=Column(String(100),default="")
    username=Column(String(150),default="")
    event_count=Column(Integer,default=0)
    status=Column(String(30),default="OPEN")
    created_at=Column(DateTime(timezone=True),default=utc_now,nullable=False)
    case=relationship("InvestigationCase",back_populates="findings")
class AuditEntry(Base):
    __tablename__="audit_entries"
    id=Column(Integer,primary_key=True)
    case_id=Column(Integer,ForeignKey("investigation_cases.id"),nullable=False,index=True)
    action=Column(String(100),nullable=False)
    actor=Column(String(100),default="analyst")
    details=Column(Text,default="")
    created_at=Column(DateTime(timezone=True),default=utc_now,nullable=False)
    case=relationship("InvestigationCase",back_populates="audit_entries")
class IncidentRecord(Base):
    __tablename__="incident_records"
    id=Column(Integer,primary_key=True)
    title=Column(String(250),nullable=False)
    severity=Column(String(20),nullable=False,default="MEDIUM")
    description=Column(Text,default="")
    status=Column(String(30),nullable=False,default="NEW")
    response_actions=Column(JSON,nullable=False,default=list)
    created_at=Column(DateTime(timezone=True),default=utc_now,nullable=False)
    updated_at=Column(DateTime(timezone=True),default=utc_now,onupdate=utc_now,nullable=False)
