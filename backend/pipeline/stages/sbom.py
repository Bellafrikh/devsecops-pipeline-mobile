"""
Stage 3+4 — SBOM Generation + Vulnerability Scan
Uses Syft (CycloneDX) + Grype
"""
import os
import json
from typing import Any, Dict

from pipeline.stages.base import BaseStage, StageFailure, StageWarning


class SBOMStage(BaseStage):
    name = "sbom"
    display_name = "SBOM + Vulnerability Scan"
    order = 3

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        repo_dir = context.get("repo_dir")
        workspace = context["workspace_path"]

        if not repo_dir or not os.path.exists(repo_dir):
            raise StageFailure("No repository directory found for SBOM generation")

        sbom_path = os.path.join(workspace, "sbom.json")
        vuln_path = os.path.join(workspace, "vuln-report.json")

        # ── Generate SBOM with Syft ───────────────────────────────
        await self.log(f"Generating SBOM from source directory with Syft...")
        rc, stdout, stderr = await self.run_cmd([
            "syft", f"dir:{repo_dir}",
            "-o", f"cyclonedx-json={sbom_path}",
            "--quiet"
        ])
        if rc != 0 and not os.path.exists(sbom_path):
            await self.log(f"Syft failed (rc={rc}), trying alternate method...", "WARN")
            # Fallback: basic SBOM from project files
            sbom_path = await self._generate_basic_sbom(repo_dir, workspace)

        if os.path.exists(sbom_path):
            with open(sbom_path) as f:
                sbom_data = json.load(f)
            component_count = len(sbom_data.get("components", []))
            await self.log(f"SBOM generated: {component_count} components identified")
            context["sbom_path"] = sbom_path
            context["sbom_data"] = sbom_data
            context["sbom_component_count"] = component_count
        else:
            await self.log("SBOM generation skipped — Syft not available", "WARN")
            context["sbom_data"] = {}
            context["sbom_component_count"] = 0

        # ── Scan for Vulnerabilities with Grype ──────────────────
        await self.log("Scanning SBOM for CVEs with Grype...")
        vulnerabilities = []

        if os.path.exists(sbom_path):
            # Disable auto-update to prevent hanging on slow connection, and bypass staleness checks
            os.environ["GRYPE_DB_AUTO_UPDATE"] = "false"
            os.environ["GRYPE_DB_VALIDATE_AGE"] = "false"
            rc, _, _ = await self.run_cmd([
                "grype", f"sbom:{sbom_path}",
                "-o", "json",
                "--file", vuln_path,
                "--quiet"
            ])

            if rc == 0 and os.path.exists(vuln_path):
                try:
                    with open(vuln_path) as f:
                        vuln_data = json.load(f)
                    vulnerabilities = self._parse_grype(vuln_data)
                    await self.log(f"Grype scan complete: {len(vulnerabilities)} CVEs found")
                except Exception as e:
                    await self.log(f"Failed to parse Grype report: {e}", "WARN")
            else:
                await self.log("Grype scan skipped — vulnerability database not available or command failed", "WARN")
        else:
            await self.log("Skipping Grype (no SBOM available)", "WARN")

        critical = sum(1 for v in vulnerabilities if v["severity"] == "critical")
        high = sum(1 for v in vulnerabilities if v["severity"] == "high")
        medium = sum(1 for v in vulnerabilities if v["severity"] == "medium")
        low = sum(1 for v in vulnerabilities if v["severity"] == "low")

        await self.log(f"CVEs — Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")

        context["sbom_findings"] = vulnerabilities

        self.result = {
            "component_count": context.get("sbom_component_count", 0),
            "vulnerability_count": len(vulnerabilities),
            "critical": critical, "high": high, "medium": medium, "low": low,
            "findings": vulnerabilities,
        }

        return context

    def _parse_grype(self, data: dict) -> list:
        results = []
        sev_map = {"Critical": "critical", "High": "high", "Medium": "medium",
                   "Low": "low", "Negligible": "low", "Unknown": "info"}
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            pkg = match.get("artifact", {})
            results.append({
                "source": "sbom",
                "severity": sev_map.get(vuln.get("severity", "Unknown"), "info"),
                "title": f"{vuln.get('id', 'CVE')} in {pkg.get('name', 'unknown')}@{pkg.get('version', '?')}",
                "description": vuln.get("description", ""),
                "cwe": vuln.get("id", ""),
                "cvss": vuln.get("cvss", [{}])[0].get("metrics", {}).get("baseScore") if vuln.get("cvss") else None,
                "file_path": pkg.get("locations", [{}])[0].get("path") if pkg.get("locations") else None,
            })
        return results

    async def _generate_basic_sbom(self, repo_dir: str, workspace: str) -> str:
        """Basic SBOM fallback using project directory parsing"""
        sbom_path = os.path.join(workspace, "sbom.json")
        components = []
        try:
            for root, dirs, files in os.walk(repo_dir):
                dirs[:] = [d for d in dirs if d not in [".git", "build", ".gradle"]]
                for name in files:
                    if name.endswith(".jar") or name.endswith(".aar"):
                        lib_name = name.replace(".jar", "").replace(".aar", "")
                        components.append({
                            "type": "library",
                            "name": lib_name,
                            "version": "unknown",
                            "purl": f"pkg:maven/{lib_name}",
                        })
        except Exception as e:
            await self.log(f"Basic SBOM failed: {e}", "WARN")

        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": components}
        with open(sbom_path, "w") as f:
            json.dump(sbom, f, indent=2)
        return sbom_path
