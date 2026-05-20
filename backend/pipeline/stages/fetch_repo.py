"""
Stage 1 — Fetch Repo
Clones the GitHub repo and detects project type
"""
import os
import asyncio
from typing import Any, Dict

from pipeline.stages.base import BaseStage, StageFailure


class FetchRepoStage(BaseStage):
    name = "fetch_repo"
    display_name = "Fetch Repo"
    order = 1

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        import shutil
        github_url = context["github_url"]
        branch = context.get("branch", "main")
        workspace = context["workspace_path"]
        project_id = context.get("project_id", "default")

        repo_dir = os.path.join(workspace, "repo")
        os.makedirs(repo_dir, exist_ok=True)

        cache_base = os.path.join(os.path.dirname(workspace), "cache")
        project_cache_dir = os.path.join(cache_base, f"project-{project_id}")
        os.makedirs(cache_base, exist_ok=True)

        # ── Clone / Fetch ────────────────────────────────────────
        if os.path.exists(project_cache_dir) and os.path.exists(os.path.join(project_cache_dir, ".git")):
            await self.log(f"Found cached repository for project. Fetching latest changes for branch: {branch}...")
            rc, _, err = await self.run_cmd(
                [
                    "git",
                    "-c", "http.version=HTTP1.1",
                    "-c", "http.postBuffer=524288000",
                    "-c", "http.lowSpeedLimit=0",
                    "-c", "http.lowSpeedTime=999999",
                    "fetch",
                    "--depth=1",
                    "origin",
                    branch
                ],
                cwd=project_cache_dir
            )
            if rc == 0:
                rc2, _, err2 = await self.run_cmd(["git", "checkout", "-f", branch], cwd=project_cache_dir)
                rc3, _, err3 = await self.run_cmd(["git", "reset", "--hard", f"origin/{branch}"], cwd=project_cache_dir)
                if rc3 == 0:
                    await self.log("Repository cache updated successfully.")
                else:
                    await self.log(f"Failed to reset cache: {err3}. Will re-clone...", "WARN")
                    shutil.rmtree(project_cache_dir, ignore_errors=True)
            else:
                await self.log(f"Failed to fetch changes: {err}. Will re-clone...", "WARN")
                shutil.rmtree(project_cache_dir, ignore_errors=True)

        if not os.path.exists(project_cache_dir):
            await self.log(f"Cloning {github_url} @ {branch} (first-time setup)...")
            await self.log("[INFO] Fetching remote repository. Depending on repository size and network speed, this may take a moment...", "INFO")
            rc, _, err = await self.run_cmd(
                [
                    "git",
                    "-c", "http.version=HTTP1.1",
                    "-c", "http.postBuffer=524288000",
                    "-c", "http.lowSpeedLimit=0",
                    "-c", "http.lowSpeedTime=999999",
                    "clone",
                    "--depth=1",
                    "--single-branch",
                    "--no-tags",
                    "--progress",
                    "--branch", branch,
                    github_url,
                    project_cache_dir
                ]
            )
            if rc != 0:
                # Try default branch
                await self.log("Branch not found, trying default branch...", "WARN")
                rc, _, err = await self.run_cmd(
                    [
                        "git",
                        "-c", "http.version=HTTP1.1",
                        "-c", "http.postBuffer=524288000",
                        "-c", "http.lowSpeedLimit=0",
                        "-c", "http.lowSpeedTime=999999",
                        "clone",
                        "--depth=1",
                        "--single-branch",
                        "--no-tags",
                        "--progress",
                        github_url,
                        project_cache_dir
                    ]
                )
                if rc != 0:
                    raise StageFailure(f"git clone failed: {err[:300]}")

        # Copy from cache to workspace
        await self.log("Copying files to build workspace...")
        try:
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir, ignore_errors=True)
            shutil.copytree(project_cache_dir, repo_dir, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        except Exception as e:
            raise StageFailure(f"Failed to prepare workspace directory: {e}")

        # ── Get commit SHA ────────────────────────────────────────
        rc, sha, _ = await self.run_cmd(["git", "rev-parse", "HEAD"], cwd=project_cache_dir)
        if rc == 0:
            context["commit_sha"] = sha.strip()
            await self.log(f"Commit: {sha.strip()[:12]}")

        context["repo_dir"] = repo_dir

        # ── Detect project type ───────────────────────────────────
        project_type = self._detect_project_type(repo_dir)
        await self.log(f"Project type detected: {project_type}")
        context["project_type"] = project_type

        self.result = {
            "repo_dir": repo_dir,
            "project_type": project_type,
            "commit_sha": context.get("commit_sha"),
        }
        return context

    def _detect_project_type(self, repo_dir: str) -> str:
        files = os.listdir(repo_dir)
        if "pubspec.yaml" in files:
            return "flutter"
        if "package.json" in files and "android" in files:
            return "react_native"
        if "build.gradle" in files or "build.gradle.kts" in files:
            return "android"
        if "gradlew" in files:
            return "android"
        # Check subdirectories
        for f in ["app/build.gradle", "android/build.gradle"]:
            if os.path.exists(os.path.join(repo_dir, f)):
                return "android"
        return "unknown"
