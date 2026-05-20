"""
FastAPI Main Application
Mobile DevSecOps Platform Backend
"""
import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional
import yaml
from datetime import datetime

from models.database import init_db, get_db, Run, Stage, Finding, Ticket, Policy, Project, RunStatus
from models.schemas import (
    RunCreate, RunOut, StageOut, FindingOut, TicketOut, TicketUpdate,
    PolicyCreate, PolicyUpdate, PolicyOut, ProjectCreate, ProjectUpdate, ProjectOut
)
from pipeline.ws_manager import ws_manager
from pipeline.runner import execute_pipeline, cancel_run


# ─── App Lifecycle ─────────────────────────────────────────────────────────────

async def _cleanup_orphaned_runs():
    from models.database import AsyncSessionLocal, Run, Stage, RunStatus, StageStatus
    async with AsyncSessionLocal() as db:
        try:
            # Mark all active runs as cancelled on startup
            result = await db.execute(
                select(Run).where(Run.status.in_([RunStatus.RUNNING, RunStatus.PENDING]))
            )
            orphans = result.scalars().all()
            for r in orphans:
                r.status = RunStatus.CANCELLED
                r.finished_at = datetime.utcnow()
                
            # Skip any active stages
            stages_res = await db.execute(
                select(Stage).where(Stage.status.in_([StageStatus.RUNNING, StageStatus.PENDING]))
            )
            orphan_stages = stages_res.scalars().all()
            for s in orphan_stages:
                s.status = StageStatus.SKIPPED
                s.finished_at = datetime.utcnow()
                
            if orphans or orphan_stages:
                await db.commit()
                print(f"[Startup] Cleaned up {len(orphans)} orphaned runs and {len(orphan_stages)} stages.")
        except Exception as e:
            print(f"[Startup] Failed to clean up orphaned runs: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _cleanup_orphaned_runs()
    await _seed_default_policy()
    yield

app = FastAPI(
    title="Mobile DevSecOps Platform",
    description="Custom CI/CD pipeline for mobile security scanning",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Projects ──────────────────────────────────────────────────────────────────

@app.get("/api/projects", response_model=List[ProjectOut])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(desc(Project.created_at)))
    return result.scalars().all()


@app.post("/api/projects", response_model=ProjectOut, status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(**data.model_dump())
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@app.get("/api/projects/{project_id}", response_model=ProjectOut)
async def get_project(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@app.put("/api/projects/{project_id}", response_model=ProjectOut)
async def update_project(project_id: int, data: ProjectUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    for k, v in data.model_dump(exclude_none=True).items():
        setattr(project, k, v)
    await db.commit()
    await db.refresh(project)
    return project


@app.delete("/api/projects/{project_id}", status_code=204)
async def delete_project(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    await db.delete(project)
    await db.commit()


# ─── Runs ──────────────────────────────────────────────────────────────────────

@app.post("/api/runs", response_model=RunOut, status_code=201)
async def create_run(
    data: RunCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    # Load policy snapshot
    policy_snapshot = None
    if data.policy_id:
        pol_result = await db.execute(select(Policy).where(Policy.id == data.policy_id))
        pol = pol_result.scalar_one_or_none()
        if pol:
            try:
                policy_snapshot = yaml.safe_load(pol.yaml_content)
            except Exception:
                pass

    # Find or create project
    result = await db.execute(select(Project).where(Project.github_url == data.github_url))
    project = result.scalar_one_or_none()
    
    if not project:
        project_name = data.github_url.split("/")[-1].replace(".git", "")
        project = Project(
            name=project_name,
            github_url=data.github_url,
            branch=data.branch,
            policy_id=data.policy_id
        )
        db.add(project)
        await db.commit()
        await db.refresh(project)

    run = Run(
        github_url=data.github_url,
        branch=data.branch,
        project_id=project.id,
        policy_snapshot=policy_snapshot,
        status=RunStatus.PENDING,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    # Launch pipeline in background
    background_tasks.add_task(execute_pipeline, run.id)

    return run


@app.post("/api/webhook/github", status_code=202)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Receives push events from GitHub, creates a run, and triggers the pipeline.
    Expects a webhook configured with content-type 'application/json'.
    """
    payload = await request.json()
    
    # We only care about push events (or pull_request if configured)
    if "repository" not in payload:
        return {"status": "ignored", "reason": "No repository in payload"}
        
    github_url = payload["repository"].get("html_url")
    if not github_url:
        return {"status": "ignored", "reason": "No html_url in payload"}
        
    # Extract branch (ref)
    branch = "main"
    ref = payload.get("ref", "")
    if ref.startswith("refs/heads/"):
        branch = ref.replace("refs/heads/", "")
        
    # Extract commit sha
    commit_sha = payload.get("after") or payload.get("head_commit", {}).get("id")
    
    # Find or create project
    result = await db.execute(select(Project).where(Project.github_url == github_url))
    project = result.scalar_one_or_none()
    
    if not project:
        project_name = github_url.split("/")[-1].replace(".git", "")
        project = Project(
            name=project_name,
            github_url=github_url,
            branch=branch,
        )
        db.add(project)
        await db.commit()
        await db.refresh(project)

    # Use project's policy if any
    policy_snapshot = None
    if project.policy_id:
        pol_result = await db.execute(select(Policy).where(Policy.id == project.policy_id))
        pol = pol_result.scalar_one_or_none()
        if pol:
            try:
                policy_snapshot = yaml.safe_load(pol.yaml_content)
            except Exception:
                pass

    run = Run(
        github_url=github_url,
        branch=branch,
        commit_sha=commit_sha,
        project_id=project.id,
        policy_snapshot=policy_snapshot,
        status=RunStatus.PENDING,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    # Launch pipeline in background
    background_tasks.add_task(execute_pipeline, run.id)

    return {"status": "accepted", "run_id": run.id, "message": "Pipeline triggered"}



@app.get("/api/runs", response_model=List[RunOut])
async def list_runs(
    project_id: Optional[int] = None,
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    q = select(Run).order_by(desc(Run.created_at)).limit(limit)
    if project_id:
        q = q.where(Run.project_id == project_id)
    result = await db.execute(q)
    return result.scalars().all()


@app.post("/api/runs/{run_id}/cancel", status_code=200)
async def cancel_run_endpoint(run_id: int, db: AsyncSession = Depends(get_db)):
    """Signal a running pipeline to stop gracefully after the current stage."""
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status not in (RunStatus.RUNNING, RunStatus.PENDING):
        raise HTTPException(400, f"Run is not active (status: {run.status})")
    cancel_run(run_id)
    if run.status == RunStatus.PENDING:
        run.status = RunStatus.CANCELLED
        run.finished_at = datetime.utcnow()
        await db.commit()
        await ws_manager.broadcast_to_run(run_id, {"event": "run_cancelled", "run_id": run_id})
        await ws_manager.broadcast_global({"event": "run_cancelled", "run_id": run_id})
        await ws_manager.send_run_complete(run_id, RunStatus.CANCELLED.value, {})
        return {"status": "cancelled", "run_id": run_id}
    await ws_manager.broadcast_to_run(run_id, {"event": "run_cancelling", "run_id": run_id})
    await ws_manager.broadcast_global({"event": "run_cancelling", "run_id": run_id})
    return {"status": "cancelling", "run_id": run_id}


@app.post("/api/runs/{run_id}/relaunch", response_model=RunOut, status_code=201)
async def relaunch_run(run_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Create and launch a new run with the same parameters as an existing run."""
    result = await db.execute(select(Run).where(Run.id == run_id))
    original = result.scalar_one_or_none()
    if not original:
        raise HTTPException(404, "Run not found")

    new_run = Run(
        github_url=original.github_url,
        branch=original.branch,
        project_id=original.project_id,
        policy_snapshot=original.policy_snapshot,
        status=RunStatus.PENDING,
    )
    db.add(new_run)
    await db.commit()
    await db.refresh(new_run)
    background_tasks.add_task(execute_pipeline, new_run.id)
    return new_run


@app.get("/api/runs/{run_id}", response_model=RunOut)
async def get_run(run_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(404, "Run not found")
    return run


@app.get("/api/runs/{run_id}/stages", response_model=List[StageOut])
async def get_run_stages(run_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Stage).where(Stage.run_id == run_id).order_by(Stage.order)
    )
    return result.scalars().all()


@app.get("/api/runs/{run_id}/findings", response_model=List[FindingOut])
async def get_run_findings(
    run_id: int,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = select(Finding).where(Finding.run_id == run_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if source:
        q = q.where(Finding.source == source)
    result = await db.execute(q)
    return result.scalars().all()


@app.get("/api/runs/{run_id}/tickets", response_model=List[TicketOut])
async def get_run_tickets(run_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Ticket).where(Ticket.run_id == run_id))
    return result.scalars().all()


@app.get("/api/runs/{run_id}/release-notes")
async def get_release_notes(run_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(404, "Run not found")
    return {"run_id": run_id, "content": run.release_notes or ""}


# ─── Tickets ───────────────────────────────────────────────────────────────────

@app.get("/api/tickets", response_model=List[TicketOut])
async def list_tickets(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = select(Ticket).order_by(desc(Ticket.created_at))
    if status:
        q = q.where(Ticket.status == status)
    if severity:
        q = q.where(Ticket.severity == severity)
    result = await db.execute(q)
    return result.scalars().all()


@app.patch("/api/tickets/{ticket_id}", response_model=TicketOut)
async def update_ticket(ticket_id: int, data: TicketUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Ticket).where(Ticket.id == ticket_id))
    ticket = result.scalar_one_or_none()
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    for k, v in data.model_dump(exclude_none=True).items():
        setattr(ticket, k, v)
    await db.commit()
    await db.refresh(ticket)
    return ticket


# ─── Policies ──────────────────────────────────────────────────────────────────

@app.get("/api/policies", response_model=List[PolicyOut])
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).order_by(desc(Policy.created_at)))
    return result.scalars().all()


@app.post("/api/policies", response_model=PolicyOut, status_code=201)
async def create_policy(data: PolicyCreate, db: AsyncSession = Depends(get_db)):
    # Validate YAML
    try:
        yaml.safe_load(data.yaml_content)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")
    policy = Policy(**data.model_dump())
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@app.get("/api/policies/{policy_id}", response_model=PolicyOut)
async def get_policy(policy_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    return policy


@app.put("/api/policies/{policy_id}", response_model=PolicyOut)
async def update_policy(policy_id: int, data: PolicyUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    if data.yaml_content:
        try:
            yaml.safe_load(data.yaml_content)
        except yaml.YAMLError as e:
            raise HTTPException(400, f"Invalid YAML: {e}")
    for k, v in data.model_dump(exclude_none=True).items():
        setattr(policy, k, v)
    await db.commit()
    await db.refresh(policy)
    return policy


@app.delete("/api/policies/{policy_id}", status_code=204)
async def delete_policy(policy_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    if policy.is_default:
        raise HTTPException(400, "Cannot delete the default policy")
    await db.delete(policy)
    await db.commit()


# ─── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/runs/{run_id}")
async def ws_run(websocket: WebSocket, run_id: int):
    await ws_manager.connect(websocket, run_id)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, run_id)


@app.websocket("/ws/global")
async def ws_global(websocket: WebSocket):
    await ws_manager.connect_global(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect_global(websocket)


# ─── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    runs_result = await db.execute(select(func.count()).select_from(Run))
    total_runs = runs_result.scalar()

    findings_result = await db.execute(select(func.count()).select_from(Finding))
    total_findings = findings_result.scalar()

    tickets_result = await db.execute(select(func.count()).select_from(Ticket))
    total_tickets = tickets_result.scalar()

    projects_result = await db.execute(select(func.count()).select_from(Project))
    total_projects = projects_result.scalar()

    return {
        "total_runs": total_runs,
        "total_findings": total_findings,
        "total_tickets": total_tickets,
        "total_projects": total_projects,
    }


# ─── Seed ──────────────────────────────────────────────────────────────────────

async def _seed_default_policy():
    """Seed the default policy from file if no policies exist"""
    from models.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Policy).where(Policy.is_default == True))
        existing = result.scalar_one_or_none()
        if existing:
            return

        policy_path = os.path.join(
            os.path.dirname(__file__), "../policies/default-policy.yaml"
        )
        if os.path.exists(policy_path):
            with open(policy_path) as f:
                content = f.read()
        else:
            content = """version: "1.0"
name: "Default Security Policy"
thresholds:
  critical: 0
  high: 5
  medium: 20
  low: 50
scanners:
  mobsf:
    enabled: true
    fail_on_score_below: 40
  sbom:
    enabled: true
  secret_hunter:
    enabled: true
    block_on_any_secret: true
  crypto_lint:
    enabled: true
    severity: warn
ai_triage:
  enabled: true
  ticket_auto_create: true
  release_notes: true
"""
        policy = Policy(
            name="Default Security Policy",
            description="Standard mobile security policy — critical=0 blocks pipeline",
            yaml_content=content,
            is_default=True,
        )
        db.add(policy)
        await db.commit()


# ─── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "Mobile DevSecOps Platform"}
