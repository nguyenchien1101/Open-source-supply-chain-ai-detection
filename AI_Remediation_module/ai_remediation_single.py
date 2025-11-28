#!/usr/bin/env python3
"""
One-file AI Remediation (Gemini)
--------------------------------
Input: paths to Semgrep / Trivy / Snyk JSON reports
Process: parse findings -> (optional) read code context -> call Gemini -> output unified report (JSON + HTML)

Usage
-----
python ai_remediation_single.py \
  --semgrep path/to/semgrep.json \
  --trivy  path/to/trivy.json \
  --snyk   path/to/snyk.json \
  --repo-root . \
  --out-json unified_ai_report.json \
  --out-html unified_ai_report.html

Environment
-----------
GEMINI_API_KEY = <your key>
GEMINI_MODEL   = gemini-1.5-pro   # optional, default below

Notes
-----
- Works if you only provide a subset of reports (e.g., only --semgrep).
- If file/line exist and --repo-root is provided, will attach ±10 lines of code context.
- Keeps the implementation compact and dependency-free (uses requests only).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import html
import json
import os
import pathlib
import textwrap
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------- Data model ------------------------------------

@dataclasses.dataclass
class Finding:
    tool: str  # semgrep | trivy | snyk
    file: Optional[str]
    line: Optional[int]
    column: Optional[int]
    vulnerability: str
    severity: str
    description: str
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    code_context: Optional[str] = None

    def as_prompt(self) -> str:
        ctx = self.code_context or "(no code context available)"
        rid = self.rule_id or self.cwe or self.vulnerability

        # Nhấn mạnh: đọc ngữ cảnh code + sửa đúng dòng có "=>"
        return textwrap.dedent(f"""
        You are a senior application security engineer reviewing a REAL codebase.

        Your task:
        1) Carefully read the code snippet and understand what the function / route is doing.
        2) Identify exactly why the flagged line (marked with "=>") is vulnerable in THIS context
           (consider framework, parameters, data flow, and user input in the surrounding lines).
        3) Propose a CONCRETE fix that can be applied directly to this file: rewrite the vulnerable
           line and any closely related lines (validation, parsing, encoding, etc.).
        4) Keep the change as small and safe as possible (minimal patch).

        Finding metadata:
        - Tool: {self.tool}
        - File: {self.file}
        - Line: {self.line}
        - Rule/CWE: {rid}
        - Severity: {self.severity}
        - Title: {self.vulnerability}
        - Original Description: {self.description}

        Relevant code snippet (with line numbers, "=>" marks the vulnerable line):
        {ctx}

        IMPORTANT:
        - Use the actual variable names and APIs from the snippet (for example: Express route
          handlers, request/response objects, template engines, database clients, etc.).
        - If the issue is unsafe eval / concatenated query / missing validation, show how to rewrite
          THAT exact line to a safe pattern (e.g. JSON.parse, parameterized query, whitelist, etc.).
        - The patch should look like real production code, not pseudocode.

        Respond ONLY with valid JSON.
        DO NOT include ```json, ```markdown, or any text outside the JSON.
        The ENTIRE response must be a single JSON object. No explanations, no markdown.

        Return JSON with EXACTLY this structure:
        {{
          "rationale": "<1–3 lines explaining the risk in this specific function>",
          "fix_suggestion": "<2–4 lines describing the change, referring to real variable/function names>",
          "patch": {{
              "before": "<copy the exact vulnerable line as shown in the snippet>",
              "after": "<rewrite the exact line and related lines in a safe form>"
          }},
          "references": ["<link-1>", "<link-2>"]
        }}

        Now output the JSON ONLY:
        """)

# ----------------------------- Parsers ---------------------------------------

def parse_semgrep(path: Optional[pathlib.Path]) -> List[Finding]:
    out: List[Finding] = []
    if not path or not path.exists():
        return out
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata") or {}
        cwe = None
        if isinstance(meta, dict):
            cwe = ",".join(meta.get("cwe", [])) if isinstance(meta.get("cwe"), list) else meta.get("cwe_id")
        out.append(Finding(
            tool="semgrep",
            file=r.get("path") or extra.get("path"),
            line=(r.get("start") or {}).get("line"),
            column=(r.get("start") or {}).get("col"),
            vulnerability=r.get("check_id") or "Semgrep finding",
            severity=(extra.get("severity") or meta.get("severity") or "unknown").lower(),
            description=extra.get("message") or extra.get("lines") or "",
            rule_id=r.get("check_id"),
            cwe=cwe or None,
        ))
    return out


def parse_trivy(path: Optional[pathlib.Path]) -> List[Finding]:
    out: List[Finding] = []
    if not path or not path.exists():
        return out
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    for res in (data.get("Results") or data.get("results") or []):
        target = res.get("Target") or res.get("target")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(Finding(
                tool="trivy",
                file=target,
                line=None,
                column=None,
                vulnerability=v.get("Title") or v.get("VulnerabilityID") or "Trivy Vulnerability",
                severity=(v.get("Severity") or "unknown").lower(),
                description=v.get("Description") or v.get("PrimaryURL") or "",
                cwe=",".join(v.get("CweIDs", []) or []) or None,
                package=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion"),
            ))
        for m in res.get("Misconfigurations", []) or []:
            out.append(Finding(
                tool="trivy",
                file=target,
                line=None,
                column=None,
                vulnerability=m.get("Title") or m.get("ID") or "Trivy Misconfiguration",
                severity=(m.get("Severity") or "unknown").lower(),
                description=m.get("Description") or m.get("Message") or "",
                rule_id=m.get("ID"),
            ))
    return out


def parse_snyk(path: Optional[pathlib.Path]) -> List[Finding]:
    out: List[Finding] = []
    if not path or not path.exists():
        return out
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    vulns: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        if "vulnerabilities" in data:
            vulns = data.get("vulnerabilities") or []
        elif "issues" in data and isinstance(data["issues"], dict):
            vulns = (data["issues"].get("vulnerabilities") or []) + (data["issues"].get("licenses") or [])
        else:
            vulns = data.get("results") or []
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "vulnerabilities" in item:
                vulns.extend(item.get("vulnerabilities") or [])
    for v in vulns:
        out.append(Finding(
            tool="snyk",
            file=None,
            line=None,
            column=None,
            vulnerability=v.get("title") or v.get("id") or v.get("issueId") or "Snyk Vulnerability",
            severity=(v.get("severity") or v.get("issueData", {}).get("severity") or "unknown").lower(),
            description=v.get("description") or v.get("issueData", {}).get("issueDescription") or "",
            package=v.get("packageName") or v.get("pkgName"),
            installed_version=str(v.get("version") or v.get("pkgVersions") or "") or None,
            fixed_version=str((v.get("fix") or {}).get("version") or (v.get("fixInfo") or {}).get("upgradeTo") or "") or None,
            cwe=",".join((v.get("identifiers") or {}).get("CWE", []) or []) or None,
        ))
    return out

# -------------------------- Code context (optional) ---------------------------

def attach_code_context(findings: List[Finding], repo_root: pathlib.Path, before: int = 10, after: int = 10) -> None:
    for f in findings:
        if not f.file or not f.line:
            continue
        path = pathlib.Path(f.file)
        if not path.is_absolute():
            path = repo_root / path
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        start = max(1, f.line - before)
        end = min(len(lines), f.line + after)
        buf = []
        for i in range(start, end + 1):
            mark = "=>" if i == f.line else "  "
            buf.append(f"{mark} {i:6d} | {lines[i-1]}")
        f.code_context = "\n".join(buf)

# ----------------------------- Gemini client ---------------------------------

def call_gemini(prompt: str, model: Optional[str] = None) -> str:
    import requests, time

    # đúng chuẩn lấy API key
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = "xxxxxx"   # fallback local

    # đúng chuẩn lấy model
    model = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")



    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    last_error_text = ""
    for attempt in range(3):  # thử tối đa 3 lần
        r = requests.post(url, json=payload, timeout=60)
        if r.status_code == 429:
            # bị rate limit -> ghi lại body lỗi, đợi rồi thử lại
            last_error_text = r.text
            wait = 2 ** attempt
            print(f"[Gemini] 429 Too Many Requests, retry in {wait}s...")
            time.sleep(wait)
            continue

        if not r.ok:
            # lỗi khác -> trả text raw để bỏ vào report
            try:
                last_error_text = r.text
            except Exception:
                last_error_text = f"HTTP {r.status_code}"
            break

        # OK
        data = r.json()
        try:
            return data["candidates"][0]["content"]["parts"][0].get("text", "")
        except Exception:
            return json.dumps(data)

    # nếu sau 3 lần vẫn thất bại hoặc luôn 429 → trả message lỗi cho cột AI
    return f"[Gemini error] status=429 or other error. Last response: {last_error_text[:500]}"


# ----------------------------- Reporting -------------------------------------

def to_unified_dict(f: Finding, ai_text: str) -> Dict[str, Any]:
    enriched: Dict[str, Any] = {"ai_text": ai_text}
    try:
        j = json.loads(ai_text)
        if isinstance(j, dict):
            enriched = j
    except Exception:
        pass
    return {
        "Tool": f.tool,
        "File": f.file,
        "Line": f.line,
        "Severity": f.severity,
        "Vulnerability": f.vulnerability,
        "Original Description": f.description,
        "Rule/CWE": f.rule_id or f.cwe,
        "Package": f.package,
        "InstalledVersion": f.installed_version,
        "FixedVersion": f.fixed_version,
        "AI Remediation": enriched,
        "CodeContext": f.code_context,
    }


def write_json(unified: List[Dict[str, Any]], out_path: pathlib.Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out = {"generated_at": dt.datetime.utcnow().isoformat() + "Z", "findings": unified}
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")


def write_html(unified: List[Dict[str, Any]], out_path: pathlib.Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)

    def esc(x: Any) -> str:
        return html.escape(str(x)) if x is not None else ""

    total = len(unified)

    # ---------- Stats ----------
    sev_counts: Dict[str, int] = {}
    tool_counts: Dict[str, int] = {}
    for it in unified:
        sev = (it.get("Severity") or "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        tool = (it.get("Tool") or "unknown").upper()
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    sev_summary_txt = ", ".join(
        f"{k}: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: -x[1])
    )

    def build_pie_style(counts: Dict[str, int], color_map: Dict[str, str]) -> str:
        if not counts:
            return "background: #e5e7eb;"
        total_local = sum(counts.values()) or 1
        cur = 0.0
        segs = []
        for label, cnt in counts.items():
            pct = cnt * 100.0 / total_local
            start = cur
            end = cur + pct
            cur = end
            color = color_map.get(label, "#9ca3af")
            segs.append(f"{color} {start:.2f}% {end:.2f}%")
        return "background: conic-gradient(" + ", ".join(segs) + ");"

    sev_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#facc15",
        "moderate": "#facc15",
        "low": "#22c55e",
        "warning": "#fbbf24",
        "error": "#b91c1c",
        "info": "#0ea5e9",
        "unknown": "#9ca3af",
    }
    sev_pie_style = build_pie_style(sev_counts, sev_colors)

    palette = ["#6366f1", "#8b5cf6", "#06b6d4", "#16a34a", "#f97316", "#ec4899"]
    tool_color_map: Dict[str, str] = {}
    for i, t in enumerate(tool_counts.keys()):
        tool_color_map[t] = palette[i % len(palette)]
    tool_pie_style = build_pie_style(tool_counts, tool_color_map)

    # ---------- Findings timeline items ----------
    cards_html: List[str] = []
    for idx, it in enumerate(unified, start=1):
        sev_raw = (it.get("Severity") or "unknown")
        sev = sev_raw.lower()
        tool_raw = (it.get("Tool") or "")
        tool = tool_raw.upper()
        tool_lower = tool_raw.lower()

        # location
        if it.get("File"):
            loc = f"{it.get('File')}:{it.get('Line') or ''}"
        elif it.get("Location"):
            loc = str(it.get("Location"))
        else:
            loc = ""

        # AI text
        ai = it.get("AI Remediation") or {}
        if isinstance(ai, dict) and "ai_text" not in ai:
            ai_text = "\n".join(f"{k}: {v}" for k, v in ai.items())
        elif isinstance(ai, dict):
            ai_text = ai.get("ai_text", "")
        else:
            ai_text = str(ai or "")

        ctx = it.get("CodeContext") or ""
        ctx_html = ""
        if ctx:
            ctx_html = (
                "<details class='ctx-details'>"
                "<summary>View code context</summary>"
                f"<pre class='ctx-pre'><code>{html.escape(ctx)}</code></pre>"
                "</details>"
            )

        cards_html.append(
            f"""
      <div class="timeline-item" data-tool="{esc(tool_lower)}">
        <div class="timeline-rail">
          <div class="timeline-dot sev-{esc(sev)}"></div>
          <div class="timeline-line"></div>
        </div>

        <article class="finding-card">
          <header class="finding-header">
            <span class="id-tag">#{idx}</span>
            <span class="tool-badge">{esc(tool)}</span>
            <span class="sev-pill sev-{esc(sev)}">{esc(sev_raw)}</span>
            <span class="location"><code>{esc(loc)}</code></span>
          </header>

          <div class="finding-main">
            <div class="vuln">
              <div class="label">Vulnerability</div>
              <div class="text">{esc(it.get('Vulnerability'))}</div>
            </div>
            <div class="desc">
              <div class="label">Original Description</div>
              <div class="text">{esc(it.get('Original Description'))}</div>
            </div>
          </div>

          <div class="finding-ai">
            <div class="label">AI Fix Suggestion &amp; Context</div>
            <pre class="ai-pre"><code>{esc(ai_text)}</code></pre>
            {ctx_html}
          </div>
        </article>
      </div>
      """
        )

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()

    # ---------- HTML + CSS (tone C – light gradient, clean) ----------
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>AI Remediation Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #f3f4f6;
    --panel: #ffffff;
    --panel-soft: #f9fafb;
    --border: #e5e7eb;
    --text-main: #111827;
    --text-muted: #6b7280;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px 12px 32px;
    font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background:
      radial-gradient(circle at top left, rgba(59,130,246,0.13), transparent 55%),
      radial-gradient(circle at top right, rgba(244,114,182,0.13), transparent 55%),
      var(--bg);
    color: var(--text-main);
    overflow-x: hidden;
  }}
  .container {{
    max-width: 1180px;
    margin: 0 auto;
  }}
  .shell {{
    background: linear-gradient(to bottom, rgba(255,255,255,0.88), #ffffff);
    border-radius: 26px;
    padding: 20px 22px 26px;
    box-shadow:
      0 26px 60px rgba(15,23,42,0.20),
      0 0 0 1px rgba(209,213,219,0.8);
  }}

  h1 {{
    margin: 0 0 6px;
    font-size: 26px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    background: linear-gradient(90deg, #0ea5e9, #6366f1, #a855f7);
    -webkit-background-clip: text;
    color: transparent;
  }}

  .meta-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 18px;
  }}
  .chip {{
    border-radius: 999px;
    padding: 3px 10px;
    font-size: 11px;
    background: var(--panel-soft);
    border: 1px solid #e5e7eb;
    color: #374151;
  }}
  .chip span {{
    font-weight: 600;
  }}

  /* Filter bar */
  .filter-bar {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 6px 0 16px;
    flex-wrap: wrap;
  }}
  .filter-bar-label {{
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.12em;
  }}
  .filter-btn {{
    border-radius: 999px;
    border: 1px solid #e5e7eb;
    background: #f9fafb;
    padding: 4px 10px;
    font-size: 12px;
    cursor: pointer;
    color: #374151;
  }}
  .filter-btn.active {{
    background: #eef2ff;
    border-color: #6366f1;
    color: #4338ca;
    font-weight: 600;
  }}

  .summary-grid {{
    display: grid;
    grid-template-columns: minmax(0,1.4fr) minmax(0,1.1fr) minmax(0,1.1fr);
    gap: 16px;
    margin-bottom: 18px;
  }}
  .summary-block {{
    background: var(--panel-soft);
    border-radius: 18px;
    padding: 14px 15px 14px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 10px 25px rgba(15,23,42,0.06);
  }}
  .summary-block h2 {{
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: #6b7280;
    margin: 0 0 6px;
  }}
  .summary-block p {{
    margin: 0;
    font-size: 13px;
    color: #111827;
  }}

  .pie-row {{
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .pie {{
    width: 80px;
    height: 80px;
    border-radius: 999px;
    box-shadow:
      0 0 0 1px rgba(209,213,219,0.9),
      0 14px 28px rgba(15,23,42,0.12);
  }}
  .legend {{
    list-style: none;
    padding: 0;
    margin: 0;
    font-size: 12px;
    color: #374151;
  }}
  .legend li {{
    display: flex;
    align-items: center;
    margin-bottom: 2px;
  }}
  .legend-swatch {{
    width: 10px;
    height: 10px;
    border-radius: 3px;
    margin-right: 6px;
  }}

  /* Timeline layout (FIXED: không bị bó card) */
  .timeline {{
    margin-top: 8px;
  }}
  .timeline-item {{
    display: flex;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 12px;
  }}
  .timeline-rail {{
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 18px;
    flex-shrink: 0;
  }}
  .timeline-dot {{
    width: 10px;
    height: 10px;
    border-radius: 999px;
    margin-top: 6px;
    box-shadow: 0 0 0 3px #f3f4f6;
  }}
  .timeline-line {{
    flex: 1;
    width: 2px;
    margin-top: 4px;
    background: linear-gradient(to bottom, rgba(156,163,175,0.9), rgba(209,213,219,0.0));
  }}

  .timeline-dot.sev-critical {{ background: #ef4444; }}
  .timeline-dot.sev-high {{ background: #f97316; }}
  .timeline-dot.sev-medium,
  .timeline-dot.sev-moderate {{ background: #facc15; }}
  .timeline-dot.sev-low {{ background: #22c55e; }}
  .timeline-dot.sev-warning {{ background: #fbbf24; }}
  .timeline-dot.sev-error {{ background: #b91c1c; }}
  .timeline-dot.sev-info {{ background: #0ea5e9; }}
  .timeline-dot.sev-unknown {{ background: #9ca3af; }}

  .finding-card {{
    background: #ffffff;
    border-radius: 18px;
    padding: 12px 14px 12px;
    border: 1px solid var(--border);
    box-shadow:
      0 14px 32px rgba(15,23,42,0.09);
    flex: 1;
    min-width: 0;
  }}

  .finding-header {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
  }}
  .id-tag {{
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 999px;
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    color: #374151;
  }}
  .tool-badge {{
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    background: #eef2ff;
    border: 1px solid #e0e7ff;
    color: #4338ca;
  }}
  .sev-pill {{
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}
  .sev-critical {{ background: #fee2e2; color: #b91c1c; }}
  .sev-high {{ background: #ffedd5; color: #b45309; }}
  .sev-medium, .sev-moderate {{ background: #fef9c3; color: #92400e; }}
  .sev-low {{ background: #ecfdf3; color: #15803d; }}
  .sev-warning {{ background: #fffbeb; color: #92400e; }}
  .sev-error {{ background: #fee2e2; color: #b91c1c; }}
  .sev-info {{ background: #e0f2fe; color: #0369a1; }}
  .sev-unknown {{ background: #e5e7eb; color: #4b5563; }}

  .location {{
    font-size: 12px;
    color: var(--text-muted);
  }}
  .location code {{
    font-size: 12px;
  }}

  .finding-main {{
    display: grid;
    grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.3fr);
    gap: 12px;
    margin-bottom: 8px;
  }}
  .label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-muted);
    margin-bottom: 2px;
  }}
  .text {{
    font-size: 13px;
    color: var(--text-main);
    word-wrap: break-word;
  }}

  .finding-ai {{
    margin-top: 4px;
  }}
  .ai-pre {{
    margin: 0;
    background: #020617;
    color: #e5e7eb;
    border-radius: 10px;
    padding: 8px 10px;
    font-size: 12px;
    max-height: 260px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
  }}
  .ai-pre code {{
    color: inherit;
  }}

  .ctx-details {{
    margin-top: 6px;
    font-size: 12px;
  }}
  .ctx-details summary {{
    cursor: pointer;
    color: #2563eb;
  }}
  .ctx-pre {{
    margin-top: 4px;
    max-height: 200px;
    overflow-y: auto;
    background: #0f172a;
    color: #e5e7eb;
    border-radius: 8px;
    padding: 6px 8px;
    font-size: 12px;
  }}
  .ctx-pre code {{
    color: inherit;
  }}
</style>
</head>
<body>
  <div class="container">
    <div class="shell">
      <header>
        <h1>AI Remediation Report</h1>
        <div class="meta-row">
          <span>Generated at <code>{esc(generated_at)}</code></span>
          <span class="chip"><span>{total}</span> findings</span>
          <span class="chip">By severity: {esc(sev_summary_txt)}</span>
        </div>
      </header>

      <div class="filter-bar">
        <span class="filter-bar-label">Filter by tool</span>
        <button class="filter-btn active" data-filter-tool="all">All</button>
        <button class="filter-btn" data-filter-tool="semgrep">Semgrep</button>
        <button class="filter-btn" data-filter-tool="trivy">Trivy</button>
        <button class="filter-btn" data-filter-tool="snyk">Snyk</button>
      </div>

      <section class="summary-grid">
        <div class="summary-block">
          <h2>Overview</h2>
          <p>Use this dashboard to review vulnerabilities detected by Semgrep, Trivy, and Snyk, together with AI-generated remediation suggestions tailored to each finding.</p>
        </div>
        <div class="summary-block">
          <h2>Severity Distribution</h2>
          <div class="pie-row">
            <div class="pie" style="{sev_pie_style}"></div>
            <ul class="legend">
              {''.join(f'<li><span class="legend-swatch" style="background:{sev_colors.get(k,"#9ca3af")}"></span>{esc(k)}: {v}</li>' for k,v in sev_counts.items())}
            </ul>
          </div>
        </div>
        <div class="summary-block">
          <h2>Tools Coverage</h2>
          <div class="pie-row">
            <div class="pie" style="{tool_pie_style}"></div>
            <ul class="legend">
              {''.join(f'<li><span class="legend-swatch" style="background:{tool_color_map.get(k,"#9ca3af")}"></span>{esc(k)}: {v}</li>' for k,v in tool_counts.items())}
            </ul>
          </div>
        </div>
      </section>

      <section class="timeline">
        {''.join(cards_html)}
      </section>
    </div>
  </div>

<script>
  (function() {{
    const buttons = document.querySelectorAll('.filter-btn');
    const items = document.querySelectorAll('.timeline-item');

    function applyFilter(filter) {{
      items.forEach(item => {{
        const tool = item.getAttribute('data-tool') || '';
        if (filter === 'all' || tool === filter) {{
          item.style.display = '';
        }} else {{
          item.style.display = 'none';
        }}
      }});
    }}

    buttons.forEach(btn => {{
      btn.addEventListener('click', () => {{
        const filter = btn.getAttribute('data-filter-tool');
        buttons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        applyFilter(filter);
      }});
    }});
  }})();
</script>
</body>
</html>
"""
    out_path.write_text(html_doc, encoding="utf-8")



# ----------------------------- Pipeline --------------------------------------

def collect_findings(semgrep: Optional[pathlib.Path], trivy: Optional[pathlib.Path], snyk: Optional[pathlib.Path]) -> List[Finding]:
    findings: List[Finding] = []
    findings += parse_semgrep(semgrep)
    findings += parse_trivy(trivy)
    findings += parse_snyk(snyk)
    # Sort by severity desc then tool
    def rank(sev: str) -> int:
        return {"critical":5,"high":4,"medium":3,"moderate":3,"low":2,"info":1}.get((sev or '').lower(),0)
    findings.sort(key=lambda f: (-rank(f.severity), f.tool))
    return findings


def run(args) -> Tuple[List[Dict[str, Any]], int]:
    findings = collect_findings(args.semgrep, args.trivy, args.snyk)
    if not findings:
        return [], 0

    # ƯU TIÊN SEMGREP → chỉ gửi các bug Semgrep lên Gemini
    semgrep_only = [f for f in findings if f.tool == "semgrep"]

    LIMIT = 10

    if semgrep_only:
        total = len(findings)          # tổng tất cả findings để report
        send_list = semgrep_only[:LIMIT]   # chỉ Semgrep gửi lên LLM
        print(
            f"[INFO] Parsed {total} findings "
            f"({len(semgrep_only)} from Semgrep). "
            f"Sending {len(send_list)} Semgrep findings to Gemini."
        )
    else:
        # fallback: không có Semgrep → dùng behavior cũ (top N theo severity)
        total = len(findings)
        if total > LIMIT:
            print(
                f"[INFO] Parsed {total} findings, "
                f"no Semgrep found → sending top {LIMIT} to Gemini."
            )
            send_list = findings[:LIMIT]
        else:
            print(f"[INFO] Parsed {total} findings, sending all to Gemini.")
            send_list = findings

    # Gắn code context: chỉ cần cho những finding gửi lên LLM
    if args.repo_root:
        attach_code_context(send_list, args.repo_root, before=args.before, after=args.after)

    def task(f: Finding) -> Tuple[Finding, str]:
        return f, call_gemini(f.as_prompt(), model=args.model)

    pairs: List[Tuple[Finding, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        for res in ex.map(task, send_list):
            pairs.append(res)

    # Map AI result lại vào toàn bộ danh sách findings
    ai_map: Dict[Tuple[str, Optional[str], Optional[int]], str] = {}
    for f, ai in pairs:
        key = (f.tool, f.file, f.line)
        ai_map[key] = ai

    unified: List[Dict[str, Any]] = []
    for f in findings:
        key = (f.tool, f.file, f.line)
        ai_text = ai_map.get(key, "AI remediation skipped (quota saving).")
        unified.append(to_unified_dict(f, ai_text))

    return unified, total



# ---------------------------------- CLI --------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="One-file AI Remediation (Gemini)")
    ap.add_argument("--semgrep", type=pathlib.Path, default=None, help="Semgrep JSON path")
    ap.add_argument("--trivy",  type=pathlib.Path, default=None, help="Trivy JSON path")
    ap.add_argument("--snyk",   type=pathlib.Path, default=None, help="Snyk JSON path")
    ap.add_argument("--repo-root", type=pathlib.Path, default=None, help="Repo root for code context (optional)")
    ap.add_argument("--before", type=int, default=10, help="Lines of context before")
    ap.add_argument("--after",  type=int, default=10, help="Lines of context after")
    ap.add_argument("--model",  type=str, default=None, help="Gemini model (default: gemini-1.5-pro)")
    ap.add_argument("--out-json", type=pathlib.Path, default=pathlib.Path("ai_report.json"))
    ap.add_argument("--out-html", type=pathlib.Path, default=pathlib.Path("ai_report.html"))
    ap.add_argument("--max-workers", type=int, default=4)
    args = ap.parse_args()

    unified, n = run(args)
    if n == 0:
        print("No findings parsed. Provide at least one report path.")
        return 0

    write_json(unified, args.out_json)
    write_html(unified, args.out_html)
    print(f"Wrote {len(unified)} findings to:\n - {args.out_json}\n - {args.out_html}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

