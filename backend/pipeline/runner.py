"""
Pipeline Runner — Core async orchestrator
Executes stages with Fail-Fast: static analysis runs in parallel before build
"""
import os
import json
import shutil
import asyncio
import yaml
from datetime import datetime
from typing import Optional
import httpx

async def _report_github_status(github_url: str, commit_sha: str, state: str, description: str, run_id: int):
    token = os.getenv("GITHUB_TOKEN")
    if not token or not commit_sha:
        return
        
    try:
        parts = github_url.rstrip('/').split('/')
        owner = parts[-2]
        repo = parts[-1]
        if repo.endswith('.git'):
            repo = repo[:-4]
    except Exception:
        return
        
    url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{commit_sha}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    # Usually this would be your public domain
    target_url = f"http://localhost:5173/runs/{run_id}"
    
    payload = {
        "state": state,
        "target_url": target_url,
        "description": description[:140], # GitHub limits desc to 140 chars
        "context": "DevSecOps / Policy Gate"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            await client.post(url, headers=headers, json=payload, timeout=10.0)
        except Exception as e:
            print(f"GitHub status error: {e}")

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.database import Run, Stage, Finding, Ticket, Policy, RunStatus, StageStatus
from pipeline.ws_manager import ws_manager
from pipeline.stages.base import StageFailure, StageWarning
from pipeline.stages.fetch_repo import FetchRepoStage
from pipeline.stages.build_apk import BuildAPKStage
from pipeline.stages.mobsf import MobSFStage
from pipeline.stages.sbom import SBOMStage
from pipeline.stages.secret_hunter import SecretHunterStage
from pipeline.stages.crypto_lint import CryptoLintStage
from pipeline.stages.policy_gate import PolicyGateStage
from pipeline.stages.ai_triage import AITriageStage

WORKSPACE_BASE = os.getenv("WORKSPACE_DIR", "/tmp/devsecops-workspace")

# Shared set of run IDs requested to be cancelled
CANCELLED_RUNS: set = set()


def cancel_run(run_id: int):
    """Signal a running pipeline to stop after the current stage."""
    CANCELLED_RUNS.add(run_id)


# New optimized pipeline order:
# Phase 1: Clone (fast)
# Phase 2: Static analysis in PARALLEL (Fail-Fast before slow build)
# Phase 3: Build APK (slow, only if static checks pass)
# Phase 4: MobSF binary analysis
# Phase 5: Gate + AI Triage
SEQUENTIAL_STAGE_CLASSES = [
    FetchRepoStage,
    BuildAPKStage,
    MobSFStage,
    PolicyGateStage,
    AITriageStage,
]

# These 3 run in parallel after clone
PARALLEL_STATIC_CLASSES = [SBOMStage, SecretHunterStage, CryptoLintStage]

# All stages in display order (for DB record creation)
ALL_STAGE_CLASSES = [
    FetchRepoStage,
    SBOMStage,
    SecretHunterStage,
    CryptoLintStage,
    BuildAPKStage,
    MobSFStage,
    PolicyGateStage,
    AITriageStage,
]


async def _do_execute_pipeline(run_id: int, db: AsyncSession):
    """Main pipeline execution logic"""

    # ── Load run ───────────────────────────────────────────────
    from sqlalchemy.orm import selectinload
    result = await db.execute(select(Run).options(selectinload(Run.project)).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        return

    if run_id in CANCELLED_RUNS or run.status == RunStatus.CANCELLED:
        run.status = RunStatus.CANCELLED
        run.finished_at = datetime.utcnow()
        await db.commit()
        await ws_manager.broadcast_global({"event": "run_cancelled", "run_id": run_id})
        await ws_manager.send_run_complete(run_id, RunStatus.CANCELLED.value, {})
        CANCELLED_RUNS.discard(run_id)
        await _report_github_status(run.github_url, run.commit_sha, "error", "Pipeline execution cancelled by user", run_id)
        return

    # ── Setup workspace ────────────────────────────────────────
    workspace = os.path.join(WORKSPACE_BASE, f"run-{run_id}")
    os.makedirs(workspace, exist_ok=True)

    # ── Load policy ────────────────────────────────────────────
    policy = {}
    if run.policy_snapshot:
        policy = run.policy_snapshot
    elif run.project and run.project.policy_id:
        pol_result = await db.execute(select(Policy).where(Policy.id == run.project.policy_id))
        pol_obj = pol_result.scalar_one_or_none()
        if pol_obj:
            try:
                policy = yaml.safe_load(pol_obj.yaml_content)
            except Exception:
                pass

    # ── Initialize pipeline context ────────────────────────────
    context = {
        "run_id": run_id,
        "project_id": run.project_id,
        "github_url": run.github_url,
        "branch": run.branch,
        "workspace_path": workspace,
        "policy": policy,
    }

    # ── Update run status ──────────────────────────────────────
    run.status = RunStatus.RUNNING
    run.started_at = datetime.utcnow()
    run.workspace_path = workspace
    await db.commit()

    await ws_manager.broadcast_global({
        "event": "run_started",
        "run_id": run_id,
        "github_url": run.github_url,
    })

    # Report pending to GitHub
    await _report_github_status(run.github_url, run.commit_sha, "pending", "Running security scans...", run_id)

    # ── Create stage DB records ────────────────────────────────
    stage_records = {}
    for i, StageClass in enumerate(ALL_STAGE_CLASSES):
        stage_obj = Stage(
            run_id=run_id,
            name=StageClass.name,
            order=i + 1,
            status=StageStatus.PENDING,
        )
        db.add(stage_obj)
    await db.commit()

    # Re-query stages
    stages_result = await db.execute(select(Stage).where(Stage.run_id == run_id).order_by(Stage.order))
    stages_list = stages_result.scalars().all()
    for s in stages_list:
        stage_records[s.name] = s

    # ── Helper: run a single stage and persist result ──────────
    db_lock = asyncio.Lock()

    async def run_stage(StageClass, ctx):
        stage_instance = StageClass(run_id=run_id, ws_manager=ws_manager, db_session=db)
        
        async with db_lock:
            stage_record = stage_records.get(StageClass.name)
            if stage_record:
                stage_record.status = StageStatus.RUNNING
                stage_record.started_at = datetime.utcnow()
                await db.commit()
                
        try:
            new_ctx = await stage_instance(ctx)
        except Exception:
            new_ctx = ctx
        finally:
            async with db_lock:
                stage_record = stage_records.get(StageClass.name)
                if stage_record:
                    stage_record.status = stage_instance.status
                    stage_record.logs = "\n".join(stage_instance.log_buffer)
                    stage_record.result_data = stage_instance.result
                    stage_record.finished_at = stage_instance.finished_at
                    if stage_instance.started_at and stage_instance.finished_at:
                        stage_record.duration_seconds = (
                            stage_instance.finished_at - stage_instance.started_at
                        ).total_seconds()
                    await db.commit()
        return stage_instance, new_ctx

    # ── Execute pipeline ───────────────────────────────────────
    pipeline_failed = False
    final_status = RunStatus.PASS

    # PHASE 1: Clone
    fetch_inst, context = await run_stage(FetchRepoStage, context)
    if fetch_inst.status == StageStatus.FAIL:
        pipeline_failed = True
        final_status = RunStatus.FAIL

    # PHASE 2: Static analysis in PARALLEL (Fail-Fast)
    if not pipeline_failed and run_id not in CANCELLED_RUNS:
        await ws_manager.broadcast_global({"event": "stage_log", "run_id": run_id, "log_line": "[INFO] Running static analysis in parallel..."})
        parallel_tasks = [run_stage(SC, context) for SC in PARALLEL_STATIC_CLASSES]
        parallel_results = await asyncio.gather(*parallel_tasks)
        # Merge findings from all parallel stages into context
        for inst, partial_ctx in parallel_results:
            # Merge list-type context keys
            for key in ["all_findings", "secret_findings", "crypto_findings", "sbom_findings"]:
                if key in partial_ctx:
                    context.setdefault(key, [])
                    context[key] = list({str(f): f for f in (context[key] + partial_ctx[key])}.values())
            if inst.status == StageStatus.FAIL:
                pipeline_failed = True
                final_status = RunStatus.FAIL
    else:
        # Skip static analysis stages
        for SC in PARALLEL_STATIC_CLASSES:
            sr = stage_records.get(SC.name)
            if sr:
                sr.status = StageStatus.SKIPPED
            await ws_manager.send_stage_update(run_id, SC.name, "skipped")
        await db.commit()

    # PHASE 3: Build APK
    if not pipeline_failed and run_id not in CANCELLED_RUNS:
        build_inst, context = await run_stage(BuildAPKStage, context)
        if build_inst.status == StageStatus.FAIL:
            pipeline_failed = True
            final_status = RunStatus.FAIL
    else:
        sr = stage_records.get(BuildAPKStage.name)
        if sr:
            sr.status = StageStatus.SKIPPED
        await ws_manager.send_stage_update(run_id, BuildAPKStage.name, "skipped")
        await db.commit()

    # PHASE 4+5: MobSF, Policy Gate, AI Triage (sequential)
    for StageClass in [MobSFStage, PolicyGateStage, AITriageStage]:
        stage_record = stage_records.get(StageClass.name)

        if (pipeline_failed or run_id in CANCELLED_RUNS) and StageClass.name not in ("ai_triage",):
            if stage_record:
                stage_record.status = StageStatus.SKIPPED
            await ws_manager.send_stage_update(run_id, StageClass.name, "skipped")
            await db.commit()
            continue

        inst, context = await run_stage(StageClass, context)
        if inst.status == StageStatus.FAIL and StageClass.name != "ai_triage":
            if StageClass.name != "policy_gate":
                pipeline_failed = True
                final_status = RunStatus.FAIL

    # ── Determine final status ─────────────────────────────────
    gate = context.get("gate_result", "UNKNOWN")
    if run_id in CANCELLED_RUNS:
        final_status = RunStatus.FAIL
        gate = "CANCELLED"
        CANCELLED_RUNS.discard(run_id)
    elif gate == "WARN" and not pipeline_failed:
        final_status = RunStatus.WARN

    # ── Persist findings ───────────────────────────────────────
    all_findings = context.get("all_findings", [])
    for f in all_findings:
        finding_obj = Finding(
            run_id=run_id,
            source=f.get("source", "unknown"),
            severity=f.get("severity", "info"),
            title=f.get("title", "")[:500],
            description=f.get("description", ""),
            file_path=f.get("file_path", ""),
            line_number=f.get("line_number"),
            cwe=f.get("cwe", ""),
            cvss=f.get("cvss"),
            raw_data=f,
            group_id=f.get("group_id"),
            group_label=f.get("group_label"),
        )
        db.add(finding_obj)

    # ── Persist tickets ────────────────────────────────────────
    for t in context.get("tickets", []):
        ticket_obj = Ticket(
            run_id=run_id,
            title=t.get("title", "")[:500],
            severity=t.get("severity", "medium"),
            description=t.get("description", ""),
            affected_files=t.get("affected_files", []),
            remediation=t.get("remediation", ""),
            cwe=t.get("cwe", ""),
            group_id=t.get("group_id"),
            finding_count=t.get("finding_count", 1),
        )
        db.add(ticket_obj)

    # ── Update run summary ─────────────────────────────────────
    counts = context.get("severity_counts", {})
    run.status = final_status
    run.finished_at = datetime.utcnow()
    run.duration_seconds = (run.finished_at - run.started_at).total_seconds()
    run.critical_count = counts.get("critical", 0)
    run.high_count = counts.get("high", 0)
    run.medium_count = counts.get("medium", 0)
    run.low_count = counts.get("low", 0)
    run.secrets_count = len(context.get("secret_findings", []))
    run.crypto_issues_count = len(context.get("crypto_findings", []))
    run.mobsf_score = context.get("mobsf_score")
    run.gate_result = gate
    run.release_notes = context.get("release_notes", "")
    run.commit_sha = context.get("commit_sha")
    run.apk_path = context.get("apk_path")

    await db.commit()

    # ── Broadcast completion ───────────────────────────────────
    await ws_manager.send_run_complete(run_id, final_status.value, {
        "gate_result": gate,
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "tickets": len(context.get("tickets", [])),
        "mobsf_score": context.get("mobsf_score"),
        "duration": run.duration_seconds,
    })

    # Report final status to GitHub
    gh_state = "success"
    gh_desc = "Pipeline Passed"
    if gate == "FAIL":
        gh_state = "failure"
        gh_desc = f"Gate FAIL (Score: {run.mobsf_score}, C:{run.critical_count} H:{run.high_count})"
    elif gate == "WARN":
        gh_state = "success"
        gh_desc = "Gate WARN - Review findings"
    elif pipeline_failed:
        gh_state = "error"
        gh_desc = "Pipeline execution failed internally"
        
    await _report_github_status(run.github_url, run.commit_sha, gh_state, gh_desc, run_id)

    # ── Cleanup workspace ──────────────────────────────────────
    try:
        shutil.rmtree(workspace, ignore_errors=True)
    except Exception:
        pass


PROJECT_LOCKS = {}
PROJECT_LOCKS_LOCK = asyncio.Lock()


async def get_project_lock(project_id: int) -> asyncio.Lock:
    async with PROJECT_LOCKS_LOCK:
        if project_id not in PROJECT_LOCKS:
            PROJECT_LOCKS[project_id] = asyncio.Lock()
        return PROJECT_LOCKS[project_id]


async def execute_pipeline(run_id: int):
    """Wrapper to run pipeline with its own dedicated database session, allowing concurrent runs."""
    from models.database import AsyncSessionLocal, Run
    
    # Fetch project_id to acquire the per-project lock (preventing git/workspace race conditions)
    project_id = None
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Run.project_id).where(Run.id == run_id))
            project_id = result.scalar_one_or_none()
    except Exception as e:
        print(f"[Runner] Failed to fetch project_id for run {run_id}: {e}")

    if project_id is not None:
        lock = await get_project_lock(project_id)
        async with lock:
            async with AsyncSessionLocal() as db:
                await _do_execute_pipeline(run_id, db)
    else:
        async with AsyncSessionLocal() as db:
            await _do_execute_pipeline(run_id, db)

