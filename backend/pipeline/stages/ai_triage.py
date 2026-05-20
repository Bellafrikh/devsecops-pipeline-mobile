"""
Stage 8+9 — AI Triage + Release Security Notes
Uses Ollama (local LLM) or OpenAI for:
  - Deduplication of findings
  - Grouping by root cause
  - Ticket generation
  - Release security notes (executive summary)
"""
import os
import json
import hashlib
import asyncio
from typing import Any, Dict, List
from collections import defaultdict

from pipeline.stages.base import BaseStage

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")


class AITriageStage(BaseStage):
    name = "ai_triage"
    display_name = "AI Triage"
    order = 8

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        all_findings = context.get("all_findings", [])
        policy = context.get("policy", {})
        ai_cfg = policy.get("ai_triage", {}) if policy else {}

        if not all_findings:
            await self.log("No findings to triage")
            context["triage_groups"] = []
            context["tickets"] = []
            context["release_notes"] = "No security findings detected in this scan."
            self.result = {"groups": 0, "tickets": 0}
            return context

        await self.log(f"AI Triage: processing {len(all_findings)} findings...")
        await self.log(f"AI Provider: {AI_PROVIDER} ({OLLAMA_MODEL if AI_PROVIDER == 'ollama' else OPENAI_MODEL})")

        # ── Step 1: Rule-based deduplication ─────────────────────
        await self.log("Step 1/4: Deduplicating findings...")
        unique_findings = self._deduplicate(all_findings)
        dedup_count = len(all_findings) - len(unique_findings)
        await self.log(f"Deduplicated: {dedup_count} duplicates removed, {len(unique_findings)} unique findings")

        # ── Step 2: Rule-based grouping ───────────────────────────
        await self.log("Step 2/4: Grouping by root cause...")
        groups = self._group_findings(unique_findings)
        await self.log(f"Created {len(groups)} groups: {', '.join(groups.keys())}")

        # ── Step 3: AI ticket generation ──────────────────────────
        await self.log("Step 3/4: Generating tickets with AI (in parallel)...")
        
        async def generate_single_ticket(group_label, group_findings):
            await self.log(f"  → Launching ticket generation task for: {group_label} ({len(group_findings)} findings)")
            ticket = await self._generate_ticket(group_label, group_findings)
            ticket["group_id"] = hashlib.md5(group_label.encode()).hexdigest()[:8]
            ticket["finding_count"] = len(group_findings)
            await self.log(f"  ✓ Finished ticket generation for: {group_label}")
            return ticket

        tasks = [generate_single_ticket(label, flist) for label, flist in groups.items()]
        tickets = await asyncio.gather(*tasks)

        await self.log(f"Generated {len(tickets)} tickets")

        # ── Step 4: Release Security Notes ────────────────────────
        await self.log("Step 4/4: Generating Release Security Notes...")
        notes = await self._generate_release_notes(
            tickets,
            context.get("severity_counts", {}),
            context.get("gate_result", "UNKNOWN"),
            context.get("mobsf_score"),
        )
        await self.log("Release Security Notes generated ✓")

        context["triage_groups"] = [
            {"label": label, "findings": flist, "count": len(flist)}
            for label, flist in groups.items()
        ]
        context["tickets"] = tickets
        context["release_notes"] = notes

        self.result = {
            "original_count": len(all_findings),
            "unique_count": len(unique_findings),
            "dedup_count": dedup_count,
            "groups": len(groups),
            "tickets": len(tickets),
        }
        return context

    def _deduplicate(self, findings: List[dict]) -> List[dict]:
        """Remove exact duplicates and near-duplicates by title+file"""
        seen = {}
        for f in findings:
            key = (
                f.get("source", ""),
                f.get("title", "").lower().strip(),
                f.get("file_path", "") or "",
            )
            # Keep highest severity
            if key not in seen:
                seen[key] = f
            else:
                sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                if sev_order.get(f.get("severity", "info"), 0) > sev_order.get(seen[key].get("severity", "info"), 0):
                    seen[key] = f
        return list(seen.values())

    def _group_findings(self, findings: List[dict]) -> Dict[str, List[dict]]:
        """Group findings by root cause category"""
        GROUP_RULES = [
            ("Insecure Data Storage",       ["hardcoded", "storage", "shared_pref", "external_storage", "plaintext"]),
            ("Weak Cryptography",            ["crypto", "md5", "sha-1", "sha1", "des", "rc4", "ecb", "weak", "aes/ecb", "cryptolint"]),
            ("Hardcoded Secrets & Credentials", ["secret", "password", "api_key", "token", "key", "credential", "aws", "firebase"]),
            ("Insecure Network Communication", ["ssl", "tls", "certificate", "hostname", "http://", "trust", "mitm"]),
            ("Injection & Input Validation", ["sql", "injection", "xss", "intent", "content_provider"]),
            ("Insecure Authentication",     ["authentication", "biometric", "pin", "login", "session"]),
            ("Known CVE / Vulnerable Library", ["cve-", "sbom", "grype", "vulnerability"]),
            ("Manifest Misconfiguration",   ["manifest", "exported", "permission", "debuggable", "backup"]),
            ("Privacy & Data Leakage",      ["log", "leak", "logcat", "clipboard", "analytics"]),
            ("Weak Random / Entropy",        ["random", "entropy", "secureRandom", "math.random"]),
        ]

        groups = defaultdict(list)
        ungrouped = []

        for finding in findings:
            title_lower = (finding.get("title", "") + " " + finding.get("description", "")).lower()
            source = finding.get("source", "").lower()
            matched = False

            for group_name, keywords in GROUP_RULES:
                if any(kw in title_lower or kw in source for kw in keywords):
                    groups[group_name].append(finding)
                    matched = True
                    break

            if not matched:
                ungrouped.append(finding)

        if ungrouped:
            groups["Other Security Findings"].extend(ungrouped)

        # Sort groups by max severity
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sorted_groups = dict(
            sorted(groups.items(),
                   key=lambda x: max(sev_order.get(f.get("severity", "info"), 0) for f in x[1]),
                   reverse=True)
        )
        return sorted_groups

    async def _generate_ticket(self, group_label: str, findings: List[dict]) -> dict:
        """Use LLM to generate a structured ticket for a finding group"""
        top_severity = self._top_severity(findings)
        files = list(set(f.get("file_path", "") for f in findings if f.get("file_path")))[:5]
        cwes = list(set(f.get("cwe", "") for f in findings if f.get("cwe")))[:3]

        # Build prompt
        findings_summary = "\n".join([
            f"- [{f['severity'].upper()}] {f['title']}: {(f.get('description',''))[:100]}"
            for f in findings[:10]
        ])

        prompt = f"""You are a mobile application security expert powered by a RAG system connected to the official OWASP MASVS (Mobile Application Security Verification Standard) and Android developer documentation. Generate a security ticket for the following vulnerability group.

Group: {group_label}
Severity: {top_severity}
Affected files: {', '.join(files) or 'Multiple files'}
CWEs: {', '.join(cwes) or 'N/A'}

Findings ({len(findings)} total):
{findings_summary}

IMPORTANT REQUIREMENTS:
1. In the "remediation", you MUST cite the relevant OWASP MASVS standard (e.g., MASVS-CRYPTO, MASVS-STORAGE) and formulate the ticket as a certified OWASP recommendation.
2. Act as if you retrieved the exact paragraph from the OWASP documentation via a vector database.
3. Keep all fields EXTREMELY short and concise. Limit description to a maximum of 2 sentences, and remediation to a maximum of 3 sentences. Do not write long paragraphs.

Generate a JSON ticket with these exact fields:
{{
  "title": "concise ticket title",
  "description": "2 sentences explaining the issue and its security impact",
  "remediation": "Specific, actionable remediation steps citing the OWASP MASVS standard.",
  "severity": "{top_severity}"
}}

Respond ONLY with valid JSON, no markdown, no explanation, no backticks. Keep the total output length under 150 tokens."""

        response = await self._call_llm(prompt)

        try:
            ticket = json.loads(response)
        except Exception:
            # Fallback: structured ticket without AI
            ticket = {
                "title": f"[{top_severity.upper()}] {group_label}",
                "description": f"Found {len(findings)} {group_label.lower()} issues in the application.",
                "remediation": f"Review and fix all {group_label.lower()} findings. Consult OWASP Mobile Top 10.",
                "severity": top_severity,
            }

        ticket["affected_files"] = files
        ticket["cwe"] = cwes[0] if cwes else None
        return ticket

    async def _generate_release_notes(
        self, tickets: List[dict], counts: dict, gate: str, mobsf_score
    ) -> str:
        """Generate executive release security notes"""
        ticket_summary = "\n".join([
            f"- [{t['severity'].upper()}] {t['title']} ({t.get('finding_count',1)} findings)"
            for t in tickets
        ])

        prompt = f"""You are a security release manager. Generate concise Release Security Notes for a mobile application scan.

Scan Results:
- Gate Result: {gate}
- MobSF Security Score: {mobsf_score or 'N/A'}/100
- Critical: {counts.get('critical', 0)}, High: {counts.get('high', 0)}, Medium: {counts.get('medium', 0)}, Low: {counts.get('low', 0)}

Security Tickets ({len(tickets)} total):
{ticket_summary}

Write professional Release Security Notes in Markdown format. Keep it extremely short (under 120 words total) including:
1. Executive Summary (2 sentences, release go/no-go recommendation)
2. Key Risk Areas (bullet list of 3 items max)
3. Immediate Actions Required (if any blockers, 1 sentence max)
4. Items for Next Sprint (non-blocking, 1 sentence max)

Be direct and actionable. Limit generated text to minimize CPU inference latency."""

        notes = await self._call_llm(prompt)
        if not notes or len(notes) < 50:
            # Fallback
            go_nogo = " NO-GO" if gate == "FAIL" else (" CONDITIONAL GO" if gate == "WARN" else " GO")
            notes = f"""# Release Security Notes

## Executive Summary
Gate Result: **{gate}** {go_nogo}
This scan identified {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {counts.get('medium', 0)} medium, and {counts.get('low', 0)} low severity issues.
{"**Release is BLOCKED** — critical issues must be resolved before shipping." if gate == "FAIL" else "Release may proceed with caution."}

## Security Tickets
{chr(10).join(f"- [{t['severity'].upper()}] {t['title']}" for t in tickets)}
"""
        return notes

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM (Ollama or OpenAI) with fallback"""
        try:
            if AI_PROVIDER == "openai" and OPENAI_API_KEY:
                return await self._call_openai(prompt)
            else:
                return await self._call_ollama(prompt)
        except Exception as e:
            await self.log(f"LLM call failed: {e} — using fallback", "WARN")
            return ""

    async def _call_ollama(self, prompt: str) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            return resp.json().get("response", "")

    async def _call_openai(self, prompt: str) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": OPENAI_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1000,
                }
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    def _top_severity(self, findings: List[dict]) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return max(findings, key=lambda f: order.get(f.get("severity", "info"), 0)).get("severity", "medium")
