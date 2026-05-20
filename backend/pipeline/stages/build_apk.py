"""
Stage 5 — Build APK
Builds the APK artifact from the cloned repo
"""
import os
import asyncio
from typing import Any, Dict

from pipeline.stages.base import BaseStage, StageFailure


class BuildAPKStage(BaseStage):
    name = "build_apk"
    display_name = "Build APK"
    order = 5

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        repo_dir = context.get("repo_dir")
        workspace = context["workspace_path"]
        project_type = context.get("project_type", "unknown")

        if not repo_dir:
            raise StageFailure("Repo dir not found in context")

        await self.log(f"Building APK for project type: {project_type}...")
        await self.log("[INFO] Starting Gradle compilation. NOTE: The first execution will download the Gradle wrapper and project dependencies. This can take several minutes depending on network conditions.", "WARN")

        apk_path = await self._build_apk(repo_dir, workspace, project_type)
        if not apk_path:
            raise StageFailure("APK build failed — no .apk file produced")

        context["apk_path"] = apk_path
        await self.log(f"APK built: {apk_path}")
        await self.log(f"APK size: {os.path.getsize(apk_path) / 1024 / 1024:.2f} MB")

        self.result = {"apk_path": apk_path}
        return context

    async def _build_apk(self, repo_dir: str, workspace: str, project_type: str) -> str:
        apk_out = os.path.join(workspace, "output.apk")

        if project_type == "flutter":
            # Make flutter build command
            rc, _, _ = await self.run_cmd(
                ["flutter", "build", "apk", "--debug", "--no-pub"],
                cwd=repo_dir
            )
            if rc == 0:
                # Find the APK
                apk = self._find_apk(os.path.join(repo_dir, "build", "app", "outputs"))
                if apk:
                    import shutil
                    shutil.copy(apk, apk_out)
                    return apk_out

        elif project_type in ("android", "react_native"):
            # Set gradlew executable
            gradlew = os.path.join(repo_dir, "gradlew")
            if os.path.exists(gradlew):
                os.chmod(gradlew, 0o755)
                # Note: removed -q so output streams to the UI
                rc, _, _ = await self.run_cmd(
                    ["./gradlew", "assembleDebug", "--no-daemon", "--console=plain"],
                    cwd=repo_dir
                )
            else:
                rc, _, _ = await self.run_cmd(
                    ["gradle", "assembleDebug", "--no-daemon", "--console=plain"],
                    cwd=repo_dir
                )
            if rc == 0:
                apk = self._find_apk(repo_dir)
                if apk:
                    import shutil
                    shutil.copy(apk, apk_out)
                    return apk_out

        # Fallback: look for pre-existing APK
        apk = self._find_apk(repo_dir)
        if apk:
            import shutil
            shutil.copy(apk, apk_out)
            await self.log("Using pre-existing APK found in repo", "WARN")
            return apk_out

        return None

    def _find_apk(self, directory: str) -> str:
        for root, dirs, files in os.walk(directory):
            # Skip build cache directories
            dirs[:] = [d for d in dirs if d not in [".git", "build/intermediates"]]
            for f in files:
                if f.endswith(".apk") and "unsigned" not in f.lower():
                    return os.path.join(root, f)
        return None
