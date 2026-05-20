"""
Mobile DevSecOps Platform — Database Models
SQLAlchemy + SQLite (zero-config, self-hosted)
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Float,
    Boolean, ForeignKey, Enum as SAEnum, JSON
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import enum
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./devsecops.db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    CANCELLED = "cancelled"


class StageStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIPPED = "skipped"
    ERROR = "error"


class TicketStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    WONT_FIX = "wont_fix"


class TicketSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─── Models ──────────────────────────────────────────────────────────────────

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    github_url = Column(String(500), nullable=False)
    branch = Column(String(100), default="main")
    description = Column(Text, nullable=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs = relationship("Run", back_populates="project", cascade="all, delete-orphan")
    policy = relationship("Policy", back_populates="projects")


class Run(Base):
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    status = Column(SAEnum(RunStatus), default=RunStatus.PENDING)
    github_url = Column(String(500), nullable=False)
    branch = Column(String(100), default="main")
    commit_sha = Column(String(40), nullable=True)
    workspace_path = Column(String(500), nullable=True)
    apk_path = Column(String(500), nullable=True)
    policy_snapshot = Column(JSON, nullable=True)  # Policy at time of run
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    # Aggregated counts
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    secrets_count = Column(Integer, default=0)
    crypto_issues_count = Column(Integer, default=0)
    mobsf_score = Column(Float, nullable=True)
    gate_result = Column(String(10), nullable=True)  # PASS/FAIL/WARN
    release_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="runs")
    stages = relationship("Stage", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
    tickets = relationship("Ticket", back_populates="run", cascade="all, delete-orphan")


class Stage(Base):
    __tablename__ = "stages"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False)
    name = Column(String(100), nullable=False)
    order = Column(Integer, nullable=False)
    status = Column(SAEnum(StageStatus), default=StageStatus.PENDING)
    logs = Column(Text, default="")
    result_data = Column(JSON, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    run = relationship("Run", back_populates="stages")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False)
    source = Column(String(50), nullable=False)  # mobsf, sbom, secret_hunter, crypto_lint
    severity = Column(SAEnum(TicketSeverity), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    cwe = Column(String(50), nullable=True)
    cvss = Column(Float, nullable=True)
    raw_data = Column(JSON, nullable=True)
    is_duplicate = Column(Boolean, default=False)
    group_id = Column(String(100), nullable=True)   # AI-assigned cluster
    group_label = Column(String(200), nullable=True)  # AI-assigned label
    created_at = Column(DateTime, default=datetime.utcnow)

    run = relationship("Run", back_populates="findings")


class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False)
    title = Column(String(500), nullable=False)
    severity = Column(SAEnum(TicketSeverity), nullable=False)
    status = Column(SAEnum(TicketStatus), default=TicketStatus.OPEN)
    description = Column(Text, nullable=True)
    affected_files = Column(JSON, nullable=True)
    remediation = Column(Text, nullable=True)
    cwe = Column(String(50), nullable=True)
    group_id = Column(String(100), nullable=True)
    finding_count = Column(Integer, default=1)
    assignee = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    run = relationship("Run", back_populates="tickets")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    yaml_content = Column(Text, nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    projects = relationship("Project", back_populates="policy")


# ─── DB Init ──────────────────────────────────────────────────────────────────

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
