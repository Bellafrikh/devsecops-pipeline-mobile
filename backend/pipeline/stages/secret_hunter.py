"""
Stage 5 — SecretHunter
Detects hardcoded secrets, API keys, tokens via regex + entropy analysis
"""
import os
import re
import math
import zipfile
import json
from typing import Any, Dict, List

from pipeline.stages.base import BaseStage, StageFailure, StageWarning


# ─── Secret Patterns ──────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY",      r"AKIA[0-9A-Z]{16}",                                       "critical"),
    ("AWS_SECRET_KEY",      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("GOOGLE_API_KEY",      r"AIza[0-9A-Za-z\-_]{35}",                                  "critical"),
    ("PRIVATE_KEY",         r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",  "critical"),
    ("GITHUB_TOKEN",        r"ghp_[0-9a-zA-Z]{36}",                                     "critical"),
    ("STRIPE_SECRET",       r"sk_live_[0-9a-zA-Z]{24,}",                                "critical"),
    ("JWT_SECRET",          r"(?i)jwt.{0,20}secret.{0,20}['\"][A-Za-z0-9+/=]{20,}['\"]","high"),
    ("BEARER_TOKEN",        r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",                      "high"),
    ("FIREBASE_KEY",        r"['\"]AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}['\"]",    "high"),
    ("FACEBOOK_TOKEN",      r"EAACEdEose0cBA[0-9A-Za-z]+",                               "high"),
    ("SLACK_TOKEN",         r"xox[baprs]\-[0-9]{12}\-[0-9]{12}\-[0-9a-zA-Z]{24}",       "high"),
    ("HARDCODED_PASSWORD",  r"(?i)password\s*=\s*['\"][^'\"]{8,}['\"]",                  "high"),
    ("HARDCODED_USERNAME",  r"(?i)username\s*=\s*['\"][a-zA-Z0-9_@.]{4,}['\"]",          "medium"),
    ("DATABASE_URL",        r"(?i)(mysql|postgres|mongodb|redis)://[^'\"\s]+",            "high"),
    ("BASIC_AUTH",          r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+",             "high"),
    ("GENERIC_SECRET",      r"(?i)(?:secret|api_key|apikey|token|auth)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]", "medium"),
    ("PHONE_NUMBER",        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "low"),
    ("CREDIT_CARD",         r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "critical"),
]

ENTROPY_THRESHOLD = float(os.getenv("SECRET_ENTROPY_THRESHOLD", "4.5"))
MIN_ENTROPY_LEN = 20
BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".so", ".dex", ".class"}
TEXT_EXTENSIONS = {".java", ".kt", ".xml", ".json", ".yaml", ".yml", ".properties", ".gradle",
                   ".smali", ".html", ".js", ".ts", ".py", ".txt", ".conf", ".cfg", ".env"}


class SecretHunterStage(BaseStage):
    name = "secret_hunter"
    display_name = "SecretHunter"
    order = 5

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        repo_dir = context.get("repo_dir")
        workspace = context["workspace_path"]

        if not repo_dir or not os.path.exists(repo_dir):
            raise StageFailure("No repository directory found to scan for secrets")

        # ── Scan for Secrets ──────────────────────────────────────
        await self.log("Scanning repository files for secrets...")
        findings = []
        files_scanned = 0

        for root, dirs, files in os.walk(repo_dir):
            # Ignore git, cache, build, node modules
            dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", "build", ".gradle", "node_modules"]]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext in BINARY_EXTENSIONS:
                    continue
                files_scanned += 1
                rel_path = os.path.relpath(fpath, repo_dir)
                new_findings = await self._scan_file(fpath, rel_path)
                findings.extend(new_findings)

        await self.log(f"Scanned {files_scanned} files")

        # Deduplicate by (title, file, line)
        seen = set()
        unique = []
        for f in findings:
            key = (f["title"], f.get("file_path"), f.get("line_number"))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        critical = sum(1 for f in unique if f["severity"] == "critical")
        high = sum(1 for f in unique if f["severity"] == "high")
        medium = sum(1 for f in unique if f["severity"] == "medium")
        low = sum(1 for f in unique if f["severity"] == "low")

        await self.log(f"Secrets found — Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")
        if unique:
            await self.log(f"  {len(unique)} secrets/sensitive items detected!", "WARN")
        else:
            await self.log(" No secrets detected")

        context["secret_findings"] = unique
        self.result = {
            "files_scanned": files_scanned,
            "secrets_found": len(unique),
            "critical": critical, "high": high, "medium": medium, "low": low,
            "findings": unique,
        }
        return context

    async def _scan_file(self, fpath: str, rel_path: str) -> List[dict]:
        results = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return results

        lines = content.splitlines()
        for lineno, line in enumerate(lines, 1):
            # ── Pattern matching ──────────────────────────────────
            for pattern_name, pattern, severity in SECRET_PATTERNS:
                matches = re.findall(pattern, line)
                if matches:
                    # Truncate match for display
                    match_preview = str(matches[0])[:80]
                    results.append({
                        "source": "secret_hunter",
                        "severity": severity,
                        "title": f"Hardcoded {pattern_name}",
                        "description": f"Pattern '{pattern_name}' matched: {match_preview}",
                        "file_path": rel_path,
                        "line_number": lineno,
                        "cwe": "CWE-798",
                    })

            # ── Entropy analysis ──────────────────────────────────
            tokens = re.findall(r"['\"]([A-Za-z0-9+/=_\-]{%d,})['\"]" % MIN_ENTROPY_LEN, line)
            for token in tokens:
                entropy = self._shannon_entropy(token)
                if entropy >= ENTROPY_THRESHOLD:
                    # Check not already caught by pattern
                    if not any(r["line_number"] == lineno and "Hardcoded" in r["title"]
                               for r in results if r.get("file_path") == rel_path):
                        results.append({
                            "source": "secret_hunter",
                            "severity": "medium",
                            "title": "High-Entropy String (Potential Secret)",
                            "description": f"Entropy={entropy:.2f} (threshold={ENTROPY_THRESHOLD}), value starts: {token[:20]}...",
                            "file_path": rel_path,
                            "line_number": lineno,
                            "cwe": "CWE-798",
                        })
        return results

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
