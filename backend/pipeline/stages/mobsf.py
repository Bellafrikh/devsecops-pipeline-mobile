"""
Stage 2 — MobSF SAST Scan
Uploads APK to MobSF Docker instance and retrieves JSON report
"""
import os
import asyncio
import httpx
from typing import Any, Dict

from pipeline.stages.base import BaseStage, StageFailure, StageWarning

MOBSF_URL = os.getenv("MOBSF_URL", "http://mobsf:8000")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")


class MobSFStage(BaseStage):
    name = "mobsf"
    display_name = "MobSF SAST Scan"
    order = 2

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        apk_path = context.get("apk_path")
        if not apk_path or not os.path.exists(apk_path):
            raise StageFailure("No APK file found for MobSF scan")

        headers = {"Authorization": MOBSF_API_KEY}

        async with httpx.AsyncClient(timeout=300) as client:
            # ── Check MobSF is reachable ──────────────────────────
            await self.log(f"Connecting to MobSF at {MOBSF_URL}")
            try:
                resp = await client.get(f"{MOBSF_URL}/api/v1/scans", headers=headers)
                if resp.status_code not in (200, 403):
                    raise StageFailure(f"MobSF unreachable: HTTP {resp.status_code}")
                await self.log("MobSF connected ✓")
            except httpx.ConnectError:
                raise StageFailure(f"Cannot connect to MobSF at {MOBSF_URL}")

            # ── Upload APK ────────────────────────────────────────
            await self.log(f"Uploading APK ({os.path.getsize(apk_path)/1024/1024:.1f} MB)...")
            with open(apk_path, "rb") as f:
                resp = await client.post(
                    f"{MOBSF_URL}/api/v1/upload",
                    headers=headers,
                    files={"file": (os.path.basename(apk_path), f, "application/octet-stream")},
                )
            if resp.status_code != 200:
                raise StageFailure(f"MobSF upload failed: {resp.text[:200]}")

            upload_data = resp.json()
            file_hash = upload_data.get("hash")
            await self.log(f"Upload complete. Hash: {file_hash}")

            # ── Start Scan ────────────────────────────────────────
            await self.log("Starting static analysis scan...")
            resp = await client.post(
                f"{MOBSF_URL}/api/v1/scan",
                headers=headers,
                data={"scan_type": "apk", "file_name": os.path.basename(apk_path), "hash": file_hash},
            )
            if resp.status_code != 200:
                raise StageFailure(f"MobSF scan start failed: {resp.text[:200]}")
            await self.log("Scan started, waiting for results...")

            # ── Poll for completion ───────────────────────────────
            # MobSF scan is synchronous via /api/v1/report_json
            await asyncio.sleep(5)  # Give it a moment

            # ── Fetch JSON Report ─────────────────────────────────
            resp = await client.post(
                f"{MOBSF_URL}/api/v1/report_json",
                headers=headers,
                data={"hash": file_hash},
            )
            if resp.status_code != 200:
                raise StageFailure(f"MobSF report failed: {resp.text[:200]}")

            report = resp.json()
            await self.log(f"Report received. Security score: {report.get('security_score', 'N/A')}/100")

            # ── Parse findings ────────────────────────────────────
            findings = self._parse_report(report)
            context["mobsf_report"] = report
            context["mobsf_findings"] = findings
            
            score = report.get("security_score")
            if score is None:
                score = report.get("appsec", {}).get("security_score", 0)
                
            context["mobsf_score"] = score

            critical = sum(1 for f in findings if f["severity"] == "critical")
            high = sum(1 for f in findings if f["severity"] == "high")
            medium = sum(1 for f in findings if f["severity"] == "medium")
            low = sum(1 for f in findings if f["severity"] == "low")

            await self.log(f"Findings — Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")

            self.result = {
                "score": score,
                "findings": findings,
                "critical": critical, "high": high, "medium": medium, "low": low,
            }

            if critical > 0:
                await self.log(f"  {critical} CRITICAL findings detected", "WARN")

        return context

    def _parse_report(self, report: dict) -> list:
        findings = []
        severity_map = {
            "high": "high", "warning": "medium", "info": "low",
            "critical": "critical", "error": "high",
        }

        # Check for new MobSF v4.x format
        if "appsec" in report and isinstance(report["appsec"], dict):
            r = report["appsec"]
            for sev_key, sev_val in [("high", "high"), ("warning", "medium"), ("info", "low"), ("hotspot", "low")]:
                for item in r.get(sev_key, []):
                    findings.append({
                        "source": "mobsf",
                        "severity": sev_val,
                        "title": item.get("title") or item.get("issue") or "MobSF Issue",
                        "description": item.get("description", ""),
                        "file_path": item.get("section", ""),
                        "cwe": item.get("cwe", ""),
                    })
            return findings

        # Parse manifest issues
        for item in report.get("manifest_analysis", {}).get("manifest_issues", []):
            findings.append({
                "source": "mobsf",
                "severity": severity_map.get(item.get("severity", "info").lower(), "info"),
                "title": item.get("issue", "Manifest Issue"),
                "description": item.get("description", ""),
                "file_path": "AndroidManifest.xml",
                "cwe": item.get("cwe", ""),
            })

        # Parse code analysis
        for issue_name, issue_data in report.get("code_analysis", {}).get("findings", {}).items():
            if isinstance(issue_data, dict):
                findings.append({
                    "source": "mobsf",
                    "severity": severity_map.get(issue_data.get("level", "info").lower(), "info"),
                    "title": issue_name,
                    "description": issue_data.get("description", ""),
                    "file_path": ", ".join(issue_data.get("files", {}).keys())[:200] if issue_data.get("files") else None,
                    "cwe": issue_data.get("cwe", ""),
                    "cvss": issue_data.get("cvss", None),
                })

        # Parse binary analysis
        for item in report.get("binary_analysis", []):
            if isinstance(item, dict):
                findings.append({
                    "source": "mobsf",
                    "severity": severity_map.get(item.get("severity", "info").lower(), "info"),
                    "title": item.get("issue", "Binary Issue"),
                    "description": item.get("description", ""),
                    "file_path": None,
                    "cwe": "",
                })

        return findings
