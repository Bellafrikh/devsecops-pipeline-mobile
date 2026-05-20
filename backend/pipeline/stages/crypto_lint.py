"""
Stage 6 — CryptoLint
Detects weak cryptographic algorithms, hardcoded IVs, insecure TLS, etc.
"""
import os
import re
import zipfile
from typing import Any, Dict, List

from pipeline.stages.base import BaseStage, StageWarning


# ─── Crypto Detection Rules ───────────────────────────────────────────────────
CRYPTO_RULES = [
    # Weak algorithms
    {
        "id": "CRYPTO001",
        "name": "MD5 Hash Usage",
        "patterns": [
            r'MessageDigest\.getInstance\(["\']MD5["\']\)',
            r'DigestUtils\.md5',
            r'(?i)md5\s*\(',
        ],
        "severity": "high",
        "cwe": "CWE-327",
        "description": "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO002",
        "name": "SHA-1 Hash Usage",
        "patterns": [
            r'MessageDigest\.getInstance\(["\']SHA-1["\']\)',
            r'MessageDigest\.getInstance\(["\']SHA1["\']\)',
        ],
        "severity": "high",
        "cwe": "CWE-327",
        "description": "SHA-1 is deprecated and vulnerable to collision attacks.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO003",
        "name": "DES Cipher Usage",
        "patterns": [
            r'Cipher\.getInstance\(["\']DES[/"\']',
            r'Cipher\.getInstance\(["\']DESede[/"\']',
        ],
        "severity": "critical",
        "cwe": "CWE-326",
        "description": "DES/3DES is insecure. Use AES-256-GCM.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO004",
        "name": "ECB Mode Usage",
        "patterns": [
            r'Cipher\.getInstance\(["\']AES/ECB',
            r'Cipher\.getInstance\(["\']DES/ECB',
        ],
        "severity": "critical",
        "cwe": "CWE-327",
        "description": "ECB mode does not provide semantic security. Use GCM or CBC with proper IV.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO005",
        "name": "RC4 Usage",
        "patterns": [
            r'Cipher\.getInstance\(["\']RC4["\']\)',
            r'Cipher\.getInstance\(["\']ARCFOUR["\']\)',
        ],
        "severity": "critical",
        "cwe": "CWE-326",
        "description": "RC4 is broken. Use AES-GCM.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO006",
        "name": "Hardcoded IV/Salt",
        "patterns": [
            r'(?i)(?:byte\[\]|val|var)\s+iv\s*=\s*(?:new byte\[\]|byteArrayOf)\s*\{[^}]+\}',
            r'(?i)(?:byte\[\]|val|var)\s+salt\s*=\s*(?:new byte\[\]|byteArrayOf)\s*\{[^}]+\}',
            r'IvParameterSpec\(new byte\[\]\{',
        ],
        "severity": "high",
        "cwe": "CWE-329",
        "description": "Hardcoded IV/salt makes encryption predictable. Use SecureRandom.",
        "extensions": {".java", ".kt"},
    },
    {
        "id": "CRYPTO007",
        "name": "Weak Random (Math.random)",
        "patterns": [
            r'\bMath\.random\(\)',
            r'\bnew Random\(\)',
            r'\bjava\.util\.Random\b',
        ],
        "severity": "high",
        "cwe": "CWE-330",
        "description": "java.util.Random is not cryptographically secure. Use SecureRandom.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO008",
        "name": "SSL Hostname Verification Disabled",
        "patterns": [
            r'ALLOW_ALL_HOSTNAME_VERIFIER',
            r'setHostnameVerifier\(SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER\)',
            r'HostnameVerifier\(\)\s*\{[^}]*return\s+true',
        ],
        "severity": "critical",
        "cwe": "CWE-297",
        "description": "Hostname verification disabled — vulnerable to MITM attacks.",
        "extensions": {".java", ".kt", ".smali"},
    },
    {
        "id": "CRYPTO009",
        "name": "Trust All Certificates",
        "patterns": [
            r'X509TrustManager',
            r'checkClientTrusted\(\).*?(?:return|//)',
            r'checkServerTrusted\(\).*?(?:return|//)',
            r'getAcceptedIssuers.*?return null',
        ],
        "severity": "critical",
        "cwe": "CWE-295",
        "description": "Custom TrustManager that accepts all certificates allows MITM attacks.",
        "extensions": {".java", ".kt"},
    },
    {
        "id": "CRYPTO010",
        "name": "Weak Key Size",
        "patterns": [
            r'KeyPairGenerator\.getInstance\(["\']RSA["\']\)[^;]*initialize\((?:512|768|1024)\)',
            r'KeyGenerator\.getInstance\(["\']AES["\']\)[^;]*init\((?:64|128)\)',
        ],
        "severity": "high",
        "cwe": "CWE-326",
        "description": "Key size too small. RSA ≥ 2048 bits, AES ≥ 256 bits recommended.",
        "extensions": {".java", ".kt"},
    },
]

BINARY_EXT = {".png", ".jpg", ".gif", ".mp3", ".mp4", ".so", ".dex", ".class", ".jar"}


class CryptoLintStage(BaseStage):
    name = "crypto_lint"
    display_name = "CryptoLint"
    order = 6

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        workspace = context["workspace_path"]
        scan_dirs = []

        for key in ["smali_dir", "extract_dir", "repo_dir"]:
            d = context.get(key)
            if d and os.path.isdir(d):
                scan_dirs.append(d)

        if not scan_dirs:
            await self.log("No directories to scan for crypto issues", "WARN")
            context["crypto_findings"] = []
            self.result = {"findings": [], "issues_count": 0}
            return context

        await self.log(f"Running CryptoLint on {len(scan_dirs)} director(ies)...")
        findings = []
        files_scanned = 0

        for scan_dir in scan_dirs:
            for root, dirs, files in os.walk(scan_dir):
                dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", "build"]]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in BINARY_EXT:
                        continue
                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, scan_dir)
                    files_scanned += 1
                    new = self._scan_file(fpath, rel_path, ext)
                    findings.extend(new)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f["title"], f["file_path"], f.get("line_number"))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        critical = sum(1 for f in unique if f["severity"] == "critical")
        high = sum(1 for f in unique if f["severity"] == "high")
        medium = sum(1 for f in unique if f["severity"] == "medium")

        await self.log(f"Scanned {files_scanned} files")
        await self.log(f"Crypto issues — Critical: {critical}, High: {high}, Medium: {medium}")

        if critical > 0:
            await self.log(f"  {critical} critical crypto weaknesses found!", "WARN")
        else:
            await self.log(" No critical crypto issues detected")

        context["crypto_findings"] = unique
        self.result = {
            "files_scanned": files_scanned,
            "issues_count": len(unique),
            "critical": critical, "high": high, "medium": medium,
            "findings": unique,
        }
        return context

    def _scan_file(self, fpath: str, rel_path: str, ext: str) -> List[dict]:
        results = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return results

        for rule in CRYPTO_RULES:
            if rule["extensions"] and ext not in rule["extensions"]:
                continue
            for lineno, line in enumerate(lines, 1):
                for pattern in rule["patterns"]:
                    if re.search(pattern, line, re.DOTALL):
                        results.append({
                            "source": "crypto_lint",
                            "severity": rule["severity"],
                            "title": rule["name"],
                            "description": rule["description"],
                            "file_path": rel_path,
                            "line_number": lineno,
                            "cwe": rule["cwe"],
                            "rule_id": rule["id"],
                        })
                        break  # one match per rule per line
        return results
