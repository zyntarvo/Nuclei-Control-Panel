#!/usr/bin/env python3
"""Parse official Nuclei JSONL into panel findings. Not reconFTW."""
from __future__ import annotations

import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
SEV_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Unknown",
}


def _norm_sev(s):
    v = (s or "").strip().lower()
    if v in SEV_ORDER:
        return v
    return "unknown"


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            if isinstance(x, list):
                out.extend(str(i) for i in x if i)
            elif x:
                out.append(str(x))
        return out
    return [str(v)] if v else []


def _iter_jsonl(path, limit=8000):
    p = Path(path)
    if not p.is_file():
        return
    with p.open("r", encoding="utf-8", errors="replace") as f:
        n = 0
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
                n += 1
                if n >= limit:
                    return
            except Exception:
                continue


def parse_item(raw, job_id=None):
    if not isinstance(raw, dict):
        return None
    info = raw.get("info") or {}
    cls = info.get("classification") or {}
    cves = _as_list(cls.get("cve-id") or cls.get("cve_id"))
    blob = json.dumps(raw, ensure_ascii=False)
    extra = CVE_RE.findall(blob)
    for c in extra:
        u = c.upper()
        if u not in [x.upper() for x in cves]:
            cves.append(u)
    tags = _as_list(info.get("tags"))
    refs = _as_list(info.get("reference"))
    extracted = _as_list(raw.get("extracted-results") or raw.get("extracted_results"))
    tid = raw.get("template-id") or raw.get("templateID") or raw.get("template-path") or ""
    name = info.get("name") or tid or "finding"
    target = (
        raw.get("matched-at")
        or raw.get("matched_at")
        or raw.get("host")
        or raw.get("url")
        or raw.get("ip")
        or ""
    )
    return {
        "job_id": job_id,
        "template_id": str(tid),
        "template_path": raw.get("template-path") or raw.get("template_path") or "",
        "name": str(name),
        "severity": _norm_sev(info.get("severity")),
        "type": raw.get("type") or "",
        "target": str(target),
        "host": raw.get("host") or "",
        "ip": raw.get("ip") or "",
        "matcher": raw.get("matcher-name") or raw.get("matcher_name") or "",
        "matched_at": raw.get("matched-at") or raw.get("matched_at") or "",
        "url": raw.get("url") or "",
        "request": raw.get("request") or "",
        "response": raw.get("response") or "",
        "extracted": extracted,
        "description": info.get("description") or "",
        "tags": tags,
        "cve": [c.upper() if c.upper().startswith("CVE-") else c for c in cves],
        "cwe": _as_list(cls.get("cwe-id") or cls.get("cwe_id")),
        "cvss": cls.get("cvss-score") or cls.get("cvss_score") or "",
        "reference": refs,
        "curl": raw.get("curl-command") or raw.get("curl_command") or "",
        "timestamp": raw.get("timestamp") or "",
        "author": _as_list(info.get("author")),
    }


def collect_file(path, job_id=None, limit=8000):
    items = []
    for raw in _iter_jsonl(path, limit=limit):
        it = parse_item(raw, job_id=job_id)
        if it:
            items.append(it)
    return items


def collect_job_dir(folder, job_id=None):
    root = Path(folder) if folder else None
    if not root or not root.is_dir():
        return []
    items = []
    for name in ("findings.jsonl", "nuclei.jsonl", "output.jsonl"):
        p = root / name
        if p.is_file():
            items.extend(collect_file(p, job_id=job_id))
    if not items:
        for p in sorted(root.glob("*.jsonl")):
            items.extend(collect_file(p, job_id=job_id))
    return items


def summarize(items):
    sev = Counter(_norm_sev(x.get("severity")) for x in items)
    tags = Counter()
    for it in items:
        for t in it.get("tags") or []:
            tags[str(t).lower()] += 1
    cve_n = sum(1 for x in items if x.get("cve"))
    types = Counter(str(x.get("type") or "other") for x in items)
    return {
        "findings_total": len(items),
        "cves": cve_n,
        "severities": {k: sev.get(k, 0) for k in SEV_ORDER},
        "types": dict(types.most_common(20)),
        "top_tags": [{"id": k, "count": v} for k, v in tags.most_common(16)],
    }


def filter_items(items, severity=None, tag=None, q=None):
    out = items
    if severity:
        want = _norm_sev(severity)
        out = [x for x in out if _norm_sev(x.get("severity")) == want]
    if tag:
        t = tag.lower()
        out = [x for x in out if t in [str(z).lower() for z in (x.get("tags") or [])]]
    if q:
        needle = q.lower()
        def hit(x):
            blob = " ".join([
                str(x.get("name") or ""),
                str(x.get("template_id") or ""),
                str(x.get("target") or ""),
                " ".join(x.get("cve") or []),
                " ".join(x.get("tags") or []),
            ]).lower()
            return needle in blob
        out = [x for x in out if hit(x)]
    order = {k: i for i, k in enumerate(SEV_ORDER)}
    out.sort(key=lambda x: (order.get(_norm_sev(x.get("severity")), 99), x.get("name") or ""))
    return out


def _esc(s):
    return html.escape(str(s or ""), quote=True)


def _kv_row(label, value, mono=False):
    if value in (None, "", "—"):
        value = "—"
    cls = " class='mono'" if mono else ""
    return f"<dt>{_esc(label)}</dt><dd{cls}>{value}</dd>"


def _detail_html(it, idx):
    sev = (it.get("severity") or "").lower()
    cves = " ".join(f"<span class='cve'>{_esc(c)}</span>" for c in (it.get("cve") or [])) or "—"
    cwe = ", ".join(_esc(c) for c in (it.get("cwe") or [])) or "—"
    tags = ", ".join(_esc(t) for t in (it.get("tags") or [])) or "—"
    author = ", ".join(_esc(a) for a in (it.get("author") or [])) or "—"
    host = _esc(it.get("host"))
    if host and it.get("ip"):
        host = f"{host} ({_esc(it.get('ip'))})"
    kv = "".join([
        _kv_row("Template", _esc(it.get("template_id")), mono=True),
        _kv_row("Matched at", _esc(it.get("matched_at") or it.get("target")), mono=True),
        _kv_row("Host", host),
        _kv_row("Matcher", _esc(it.get("matcher"))),
        _kv_row("Type", _esc(it.get("type"))),
        _kv_row("CVE", cves),
        _kv_row("CWE", cwe),
        _kv_row("CVSS", _esc(it.get("cvss"))),
        _kv_row("Tags", tags),
        _kv_row("Author", author),
    ])
    parts = [
        f"<section class='v' id='f{idx}'>",
        f"<div class='vhead'><span class='sev {_esc(sev)}'>{_esc((it.get('severity') or '').upper())}</span>"
        f"<span class='vname'>{_esc(it.get('name'))}</span></div>",
        f"<dl class='kv'>{kv}</dl>",
    ]
    if it.get("description"):
        parts.append(f"<p class='desc'>{_esc(it.get('description'))}</p>")
    if it.get("extracted"):
        parts.append("<div class='sub'>Extracted</div><pre>" + _esc("\n".join(it.get("extracted") or [])) + "</pre>")
    if it.get("request"):
        parts.append("<div class='sub'>Request</div><pre>" + _esc(it.get("request")) + "</pre>")
    if it.get("response"):
        parts.append("<div class='sub'>Response</div><pre>" + _esc(it.get("response")) + "</pre>")
    if it.get("curl"):
        parts.append("<div class='sub'>cURL</div><pre>" + _esc(it.get("curl")) + "</pre>")
    refs = [r for r in (it.get("reference") or []) if r]
    if refs:
        links = "".join(f"<div><a href='{_esc(r)}' target='_blank' rel='noopener'>{_esc(r)}</a></div>" for r in refs)
        parts.append(f"<div class='sub'>References</div><div class='refs'>{links}</div>")
    parts.append("</section>")
    return "".join(parts)


def export_html(items, title="Nuclei findings"):
    counts = summarize(items)
    rows = []
    for i, it in enumerate(items):
        cves = " ".join(_esc(c) for c in (it.get("cve") or [])) or "—"
        rows.append(
            "<tr>"
            f"<td class='sev { _esc(it.get('severity')) }'>{_esc((it.get('severity') or '').upper())}</td>"
            f"<td><a class='rowlink' href='#f{i}'>{_esc(it.get('name'))}</a><div class='tid'>{_esc(it.get('template_id'))}</div></td>"
            f"<td class='mono'>{_esc(it.get('target'))}</td>"
            f"<td>{cves}</td>"
            f"<td>{_esc(it.get('matcher'))}</td>"
            "</tr>"
        )
    details = "".join(_detail_html(it, i) for i, it in enumerate(items)) or "<p>No findings</p>"
    sev_pills = "".join(
        f"<span class='pill {k}'>{SEV_LABEL[k]} {counts['severities'].get(k, 0)}</span>"
        for k in ("critical", "high", "medium", "low", "info")
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(title)}</title>
<style>
body{{background:#0a0e17;color:#e2e8f0;font-family:Inter,Segoe UI,sans-serif;margin:32px}}
h1{{color:#00ff88}} h2{{color:#00ff88;margin-top:34px;border-bottom:1px solid rgba(0,255,136,.14);padding-bottom:8px}}
.meta{{color:#94a3b8;margin-bottom:18px}}
.pill{{display:inline-block;margin:0 8px 8px 0;padding:6px 10px;border-radius:8px;font-weight:700;font-size:12px}}
.pill.critical{{background:rgba(239,68,68,.15);color:#ef4444}}
.pill.high{{background:rgba(249,115,22,.16);color:#f97316}}
.pill.medium{{background:rgba(245,158,11,.16);color:#f59e0b}}
.pill.low{{background:rgba(34,211,238,.14);color:#22d3ee}}
.pill.info{{background:rgba(148,163,184,.14);color:#94a3b8}}
table{{width:100%;border-collapse:collapse;background:#111827}}
th{{text-align:left;color:#00ff88;padding:10px;border-bottom:1px solid rgba(0,255,136,.12);font-size:12px;letter-spacing:1px}}
td{{padding:10px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}}
.tid{{color:#22d3ee;font-family:ui-monospace,monospace;font-size:12px;margin-top:4px}}
.mono{{font-family:ui-monospace,monospace;word-break:break-all}}
.rowlink{{color:#e2e8f0;text-decoration:none}} .rowlink:hover{{color:#00ff88;text-decoration:underline}}
.sev.critical{{color:#ef4444;font-weight:800}} .sev.high{{color:#f97316;font-weight:800}}
.sev.medium{{color:#f59e0b;font-weight:800}} .sev.low{{color:#22d3ee;font-weight:800}}
.sev.info,.sev.unknown{{color:#94a3b8;font-weight:800}}
.v{{background:#111827;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:18px 20px;margin:16px 0}}
.vhead{{display:flex;align-items:center;gap:12px;margin-bottom:12px}}
.vhead .sev{{padding:3px 9px;border-radius:7px;font-size:12px;background:rgba(255,255,255,.05)}}
.vname{{font-size:17px;font-weight:700;color:#fff}}
dl.kv{{display:grid;grid-template-columns:140px 1fr;gap:6px 14px;margin:0 0 12px;font-size:13px}}
dl.kv dt{{color:#94a3b8;text-transform:uppercase;letter-spacing:1px;font-size:11px;font-weight:700}}
dl.kv dd{{margin:0;color:#fff;word-break:break-word}}
.cve{{color:#00ff88;font-family:ui-monospace,monospace;margin-right:6px}}
.desc{{color:#cbd5e1;line-height:1.6;margin:6px 0 12px}}
.sub{{margin:14px 0 5px;font-size:11px;letter-spacing:1.3px;text-transform:uppercase;font-weight:700;color:#00ff88}}
pre{{background:#0a0e17;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:12px;overflow:auto;font-family:ui-monospace,monospace;font-size:12px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;max-height:520px}}
.refs a{{color:#22d3ee;font-size:12px;word-break:break-all}}
.foot{{margin-top:24px;color:#64748b;font-size:12px}}
</style></head><body>
<h1>{_esc(title)}</h1>
<div class="meta">{len(items)} findings · generated {now}</div>
<div>{sev_pills}</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Matched</th><th>CVE</th><th>Matcher</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5">No findings</td></tr>'}</tbody></table>
<h2>Details</h2>
{details}
<p class="foot">Nuclei Control Panel · Created by ZynTarvo · Engine: projectdiscovery/nuclei</p>
</body></html>"""


def export_md(items, title="Nuclei findings"):
    counts = summarize(items)
    lines = [
        f"# {title}",
        "",
        f"Total: **{len(items)}** · "
        + " · ".join(f"{SEV_LABEL[k]} {counts['severities'].get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")),
        "",
        "| Severity | Name | Template | Matched | CVE |",
        "|---|---|---|---|---|",
    ]
    for it in items:
        cves = ", ".join(it.get("cve") or []) or "—"
        lines.append(
            "| {sev} | {name} | `{tid}` | `{tgt}` | {cve} |".format(
                sev=(it.get("severity") or "").upper(),
                name=(it.get("name") or "").replace("|", "/"),
                tid=(it.get("template_id") or "").replace("|", "/"),
                tgt=(it.get("target") or "").replace("|", "/"),
                cve=cves.replace("|", "/"),
            )
        )

    lines += ["", "## Details", ""]
    for it in items:
        name = it.get("name") or it.get("template_id") or "finding"
        lines.append(f"### [{(it.get('severity') or '').upper()}] {name}")
        lines.append("")
        host = it.get("host") or ""
        if host and it.get("ip"):
            host = f"{host} ({it.get('ip')})"
        meta = [
            ("Template", "`%s`" % (it.get("template_id") or "—")),
            ("Matched at", "`%s`" % (it.get("matched_at") or it.get("target") or "—")),
            ("Host", host or "—"),
            ("Matcher", it.get("matcher") or "—"),
            ("Type", it.get("type") or "—"),
            ("CVE", ", ".join(it.get("cve") or []) or "—"),
            ("CWE", ", ".join(it.get("cwe") or []) or "—"),
            ("CVSS", str(it.get("cvss") or "—")),
            ("Tags", ", ".join(it.get("tags") or []) or "—"),
            ("Author", ", ".join(it.get("author") or []) or "—"),
        ]
        for k, v in meta:
            lines.append(f"- **{k}:** {v}")
        lines.append("")
        if it.get("description"):
            lines += [str(it.get("description")).strip(), ""]
        if it.get("extracted"):
            lines += ["**Extracted**", "```", "\n".join(it.get("extracted") or []), "```", ""]
        if it.get("request"):
            lines += ["**Request**", "```http", str(it.get("request")).rstrip(), "```", ""]
        if it.get("response"):
            lines += ["**Response**", "```http", str(it.get("response")).rstrip(), "```", ""]
        if it.get("curl"):
            lines += ["**cURL**", "```bash", str(it.get("curl")).rstrip(), "```", ""]
        refs = [r for r in (it.get("reference") or []) if r]
        if refs:
            lines.append("**References**")
            lines += [f"- {r}" for r in refs]
            lines.append("")

    lines += ["_Nuclei Control Panel · Created by ZynTarvo_"]
    return "\n".join(lines) + "\n"
