"""
Stage 7 — Policy Gate
Evaluates all findings against user-defined YAML policy thresholds.
Returns PASS / WARN / FAIL.
"""
import os
import yaml
from typing import Any, Dict, List

from pipeline.stages.base import BaseStage, StageFailure, StageWarning

DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(__file__), "../../../../policies/default-policy.yaml"
)


class PolicyGateStage(BaseStage):
    name = "policy_gate"
    display_name = "Policy Gate"
    order = 7

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        policy = context.get("policy", {})
        if not policy:
            await self.log("No custom policy found, loading default policy...")
            policy = self._load_default_policy()

        await self.log(f"Evaluating policy: {policy.get('name', 'Default')}")

        thresholds = policy.get("thresholds", {})
        scanner_cfg = policy.get("scanners", {})

        violations = []
        warnings = []

        # ── Aggregate all findings ─────────────────────────────────
        all_findings = (
            context.get("mobsf_findings", []) +
            context.get("sbom_findings", []) +
            context.get("secret_findings", []) +
            context.get("crypto_findings", [])
        )

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        await self.log(f"Total findings — C:{counts['critical']} H:{counts['high']} M:{counts['medium']} L:{counts['low']}")

        # ── Threshold checks ───────────────────────────────────────
        threshold_critical = thresholds.get("critical", 0)
        threshold_high = thresholds.get("high", 5)
        threshold_medium = thresholds.get("medium", 20)

        if counts["critical"] > threshold_critical:
            violations.append(
                f"CRITICAL findings: {counts['critical']} (threshold: {threshold_critical})"
            )
        if counts["high"] > threshold_high:
            violations.append(
                f"HIGH findings: {counts['high']} (threshold: {threshold_high})"
            )
        if counts["medium"] > threshold_medium:
            warnings.append(
                f"MEDIUM findings: {counts['medium']} (threshold: {threshold_medium})"
            )

        # ── MobSF score check ──────────────────────────────────────
        mobsf_cfg = scanner_cfg.get("mobsf", {})
        if mobsf_cfg.get("enabled", True):
            score = context.get("mobsf_score")
            min_score = mobsf_cfg.get("fail_on_score_below", 40)
            if score is not None and score < min_score:
                violations.append(
                    f"MobSF security score: {score:.1f}/100 (minimum: {min_score})"
                )

        # ── Secret scan check ──────────────────────────────────────
        secret_cfg = scanner_cfg.get("secret_hunter", {})
        if secret_cfg.get("enabled", True) and secret_cfg.get("block_on_any_secret", True):
            secrets = [f for f in context.get("secret_findings", [])
                       if f["severity"] in ("critical", "high")]
            if secrets:
                violations.append(
                    f"Secrets detected: {len(secrets)} high/critical secrets found (policy: block)"
                )

        # ── Crypto lint check ──────────────────────────────────────
        crypto_cfg = scanner_cfg.get("crypto_lint", {})
        if crypto_cfg.get("enabled", True):
            crypto_sev = crypto_cfg.get("severity", "warn")
            crypto_critical = [f for f in context.get("crypto_findings", [])
                               if f["severity"] == "critical"]
            if crypto_critical:
                if crypto_sev == "block" or crypto_sev == "fail":
                    violations.append(
                        f"Critical crypto weaknesses: {len(crypto_critical)} found (policy: block)"
                    )
                else:
                    warnings.append(
                        f"Critical crypto weaknesses: {len(crypto_critical)} found (policy: warn)"
                    )

        # ── Determine gate result ─────────────────────────────────
        await self.log("─" * 50)
        if violations:
            for v in violations:
                await self.log(f"   FAIL: {v}", "ERROR")
            gate_result = "FAIL"
        elif warnings:
            for w in warnings:
                await self.log(f"    WARN: {w}", "WARN")
            gate_result = "WARN"
        else:
            gate_result = "PASS"

        await self.log(f"─" * 50)
        await self.log(f"Policy Gate Result: {gate_result}")

        context["gate_result"] = gate_result
        context["gate_violations"] = violations
        context["gate_warnings"] = warnings
        context["all_findings"] = all_findings
        context["severity_counts"] = counts

        self.result = {
            "gate_result": gate_result,
            "violations": violations,
            "warnings": warnings,
            "counts": counts,
        }

        if gate_result == "FAIL":
            self.status_override = "fail"
            raise StageFailure(
                f"Policy gate FAILED: {len(violations)} violation(s). "
                "Review findings and fix or adjust policy thresholds."
            )
        elif gate_result == "WARN":
            raise StageWarning(f"Policy gate WARN: {len(warnings)} warning(s)")

        return context

    def _load_default_policy(self) -> dict:
        try:
            path = os.path.abspath(DEFAULT_POLICY_PATH)
            if os.path.exists(path):
                with open(path) as f:
                    return yaml.safe_load(f)
        except Exception:
            pass
        # Hardcoded fallback
        return {
            "name": "Default Policy (fallback)",
            "thresholds": {"critical": 0, "high": 5, "medium": 20},
            "scanners": {
                "secret_hunter": {"enabled": True, "block_on_any_secret": True},
                "crypto_lint": {"enabled": True, "severity": "warn"},
                "mobsf": {"enabled": True, "fail_on_score_below": 40},
            }
        }
