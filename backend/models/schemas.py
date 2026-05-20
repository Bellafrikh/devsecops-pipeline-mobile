"""
Pydantic schemas for request/response validation
"""
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, HttpUrl
from models.database import RunStatus, StageStatus, TicketStatus, TicketSeverity


# ─── Policy ───────────────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    yaml_content: str
    is_default: bool = False

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    yaml_content: Optional[str] = None

class PolicyOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    yaml_content: str
    is_default: bool
    created_at: datetime
    updated_at: datetime
    class Config: from_attributes = True


# ─── Project ──────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    github_url: str
    branch: str = "main"
    description: Optional[str] = None
    policy_id: Optional[int] = None

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    branch: Optional[str] = None
    description: Optional[str] = None
    policy_id: Optional[int] = None

class ProjectOut(BaseModel):
    id: int
    name: str
    github_url: str
    branch: str
    description: Optional[str]
    policy_id: Optional[int]
    created_at: datetime
    class Config: from_attributes = True


# ─── Run ──────────────────────────────────────────────────────────────────────

class RunCreate(BaseModel):
    github_url: str
    branch: str = "main"
    project_id: Optional[int] = None
    policy_id: Optional[int] = None

class StageOut(BaseModel):
    id: int
    name: str
    order: int
    status: StageStatus
    logs: str
    result_data: Optional[Dict[str, Any]]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_seconds: Optional[float]
    class Config: from_attributes = True

class RunOut(BaseModel):
    id: int
    project_id: Optional[int]
    status: RunStatus
    github_url: str
    branch: str
    commit_sha: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_seconds: Optional[float]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    secrets_count: int
    crypto_issues_count: int
    mobsf_score: Optional[float]
    gate_result: Optional[str]
    release_notes: Optional[str]
    created_at: datetime
    class Config: from_attributes = True


# ─── Finding ──────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: int
    run_id: int
    source: str
    severity: TicketSeverity
    title: str
    description: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    cwe: Optional[str]
    cvss: Optional[float]
    is_duplicate: bool
    group_id: Optional[str]
    group_label: Optional[str]
    class Config: from_attributes = True


# ─── Ticket ───────────────────────────────────────────────────────────────────

class TicketUpdate(BaseModel):
    status: Optional[TicketStatus] = None
    assignee: Optional[str] = None

class TicketOut(BaseModel):
    id: int
    run_id: int
    title: str
    severity: TicketSeverity
    status: TicketStatus
    description: Optional[str]
    affected_files: Optional[List[str]]
    remediation: Optional[str]
    cwe: Optional[str]
    group_id: Optional[str]
    finding_count: int
    assignee: Optional[str]
    created_at: datetime
    updated_at: datetime
    class Config: from_attributes = True


# ─── WebSocket Events ─────────────────────────────────────────────────────────

class WSEvent(BaseModel):
    event: str          # stage_start, stage_log, stage_end, run_complete
    run_id: int
    stage_name: Optional[str] = None
    stage_status: Optional[str] = None
    log_line: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
