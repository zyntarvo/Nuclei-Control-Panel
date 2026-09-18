#!/usr/bin/env python3
"""Nuclei Control Panel — visual operator UI. Created by ZynTarvo."""

import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import threading
import time
from functools import wraps
from pathlib import Path

import findings as F
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
)
from flask_socketio import SocketIO, emit

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
JOBS_DIR = DATA / "jobs"
SCANS_DIR = DATA / "scans"
LOGS_DIR = DATA / "logs"
NC_FILE = DATA / "notifications.json"
PDCP_FILE = DATA / "pdcp.json"
TPL_CACHE = DATA / "templates_cache.json"
for p in (DATA, JOBS_DIR, SCANS_DIR, LOGS_DIR):
    p.mkdir(parents=True, exist_ok=True)


def _load_env_file(path):
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


_load_env_file(ROOT / ".env")

NUCLEI_BIN = os.environ.get("NUCLEI_BIN") or shutil.which("nuclei") or "/usr/local/bin/nuclei"
TEMPLATES_DIR = Path(os.environ.get("NUCLEI_TEMPLATES", "/root/nuclei-templates"))
SCANS_ROOT = Path(os.environ.get("NUCLEI_SCANS", str(SCANS_DIR)))
SCANS_ROOT.mkdir(parents=True, exist_ok=True)

PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8443"))
PANEL_USER = os.environ.get("PANEL_USER", "root")
PANEL_PASS = os.environ.get("PANEL_PASS", "")
PANEL_VERSION = "1.0.0"

JOBS_FILE = DATA / "jobs.json"
_jobs_lock = threading.Lock()
_nc_lock = threading.Lock()
_followers = {}
_tpl_update = {"running": False}

POPULAR_TAGS = [
    "cve", "xss", "sqli", "rce", "lfi", "ssrf", "ssti", "redirect",
    "exposure", "misconfig", "takeover", "wordpress", "panel", "tech",
    "osint", "fuzz", "disclosure", "token", "default-login", "cloud",
    "kubernetes", "jenkins", "unauth",
]
SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Top-level dirs in nuclei-templates that are NOT runnable via -t:
#   profiles/  -> scan presets, used with -profile
#   workflows/ -> workflow files, used with -w
#   helpers/   -> wordlists/payloads referenced by templates, not standalone
# Passing them to -t makes nuclei abort with
# "no templates found in path", so we hide them from the folder picker
# and skip them defensively when building the command.
NON_TEMPLATE_DIRS = {"profiles", "workflows", "helpers"}

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET") or secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = 86400
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


@app.context_processor
def _inject_panel():
    return {"panel_version": PANEL_VERSION}


def auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("ok"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(error="Unauthorized"), 401
            return redirect("/login")
        return fn(*a, **kw)
    return wrapper


def _jobs_load():
    if JOBS_FILE.is_file():
        try:
            return json.loads(JOBS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seq": 1, "items": []}


def _jobs_save(d):
    tmp = JOBS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    tmp.replace(JOBS_FILE)


def _job_get(jid):
    d = _jobs_load()
    for it in d["items"]:
        if str(it.get("id")) == str(jid):
            return d, it
    return d, None


def _nc_load():
    if NC_FILE.is_file():
        try:
            return json.loads(NC_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"items": [], "seq": 1}


def _nc_save(d):
    NC_FILE.write_text(json.dumps(d), encoding="utf-8")


def nc_push(title, message, ntype="info"):
    with _nc_lock:
        d = _nc_load()
        item = {
            "id": d.get("seq", 1),
            "title": title,
            "message": message,
            "type": ntype,
            "ts": int(time.time()),
            "read": False,
        }
        d["seq"] = item["id"] + 1
        d.setdefault("items", []).insert(0, item)
        d["items"] = d["items"][:300]
        _nc_save(d)
    try:
        socketio.emit("nc_new", item)
    except Exception:
        pass
    return item


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(s):
    return _ANSI.sub("", s or "")


def _detect_goroot():
    try:
        return subprocess.check_output(["go", "env", "GOROOT"], text=True, timeout=5).strip()
    except Exception:
        for cand in ("/usr/lib/go-1.26", "/usr/lib/go", "/usr/local/go"):
            if os.path.isdir(os.path.join(cand, "bin")):
                return cand
        return "/usr/local/go"


def _scan_env():
    env = os.environ.copy()
    goroot = env.get("GOROOT") or _detect_goroot()
    extra = [
        os.path.join(goroot, "bin"),
        "/usr/local/go/bin",
        str(Path.home() / "go" / "bin"),
        str(Path.home() / ".local" / "bin"),
        "/usr/local/bin",
    ]
    env["PATH"] = ":".join(extra) + ":" + env.get("PATH", "")
    env["HOME"] = str(Path.home())
    env["USER"] = "root"
    env["GOROOT"] = goroot
    env["GOPATH"] = env.get("GOPATH") or str(Path.home() / "go")
    env["PYTHONUNBUFFERED"] = "1"
    pdcp = _pdcp_load().get("api_key") or ""
    if pdcp:
        env["PDCP_API_KEY"] = pdcp
    return env


def _nuclei_bin():
    cand = Path(NUCLEI_BIN)
    if cand.is_file() and os.access(cand, os.X_OK):
        return str(cand)
    w = shutil.which("nuclei")
    return w or str(cand)


def _nuclei_ready():
    p = _nuclei_bin()
    return bool(p and os.path.isfile(p) and os.access(p, os.X_OK))


def _nuclei_version():
    try:
        out = subprocess.check_output(
            [_nuclei_bin(), "-version"],
            text=True, stderr=subprocess.STDOUT, timeout=8, env=_scan_env(),
        )
        line = _strip_ansi(out).strip().splitlines()
        return (line[-1] if line else out.strip())[:120]
    except Exception:
        return None


def _engine_status():
    ready = _nuclei_ready()
    tpl_ok = TEMPLATES_DIR.is_dir()
    state = "ready" if ready else "missing"
    yaml_n = 0
    if TPL_CACHE.is_file():
        try:
            yaml_n = int(json.loads(TPL_CACHE.read_text(encoding="utf-8")).get("yaml_count") or 0)
        except Exception:
            pass
    return {
        "state": state,
        "ready": ready,
        "bin": _nuclei_bin() if ready else None,
        "version": _nuclei_version() if ready else None,
        "templates": str(TEMPLATES_DIR),
        "templates_ok": tpl_ok,
        "yaml_count": yaml_n,
        "updating": bool(_tpl_update.get("running")),
    }


def _pdcp_load():
    if PDCP_FILE.is_file():
        try:
            return json.loads(PDCP_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"api_key": ""}


def _pdcp_save(d):
    PDCP_FILE.write_text(json.dumps(d), encoding="utf-8")
    try:
        os.chmod(PDCP_FILE, 0o600)
    except Exception:
        pass


def _safe_under(path, allowed_roots):
    real = os.path.realpath(path)
    for root in allowed_roots:
        r = os.path.realpath(root)
        if real == r or real.startswith(r + os.sep):
            return real
    return None


_TARGET_RE = re.compile(
    r"^(?:https?://)?"
    r"(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)$"
)


def _validate_target(s):
    t = (s or "").strip()
    if not t or len(t) > 400 or " " in t or ".." in t:
        return None
    if any(c in t for c in ("\n", "\r", ";", "|", "`", "$", "(", ")")):
        return None
    if not _TARGET_RE.match(t):
        return None
    return t


def _parse_targets(body):
    kind = (body.get("target_kind") or "url").strip().lower()
    lines = []
    if kind == "list":
        raw = body.get("list") or ""
        lines = [x.strip() for x in str(raw).splitlines() if x.strip()]
    else:
        one = (body.get("url") or body.get("domain") or "").strip()
        if one:
            lines = [one]
    out = []
    for t in lines:
        v = _validate_target(t)
        if not v:
            raise ValueError(f"Invalid target: {t[:80]}")
        out.append(v)
    if not out:
        raise ValueError("Provide at least one URL or host")
    if len(out) > 5000:
        raise ValueError("Too many targets (max 5000)")
    return out


def _safe_tag(s):
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", s or ""))


def _int_opt(body, key, default, lo, hi):
    try:
        n = int(body.get(key, default))
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


def _build_cmd(body, job_dir: Path, targets):
    bin_path = _nuclei_bin()
    if not _nuclei_ready():
        raise ValueError("nuclei binary is not installed")
    findings = job_dir / "findings.jsonl"
    tfile = job_dir / "targets.txt"
    tfile.write_text("\n".join(targets) + "\n", encoding="utf-8")
    cmd = [bin_path, "-l", str(tfile), "-jsonl", "-o", str(findings), "-stats", "-duc"]

    folders = body.get("folders") or []
    if isinstance(folders, str):
        folders = [x.strip() for x in folders.split(",") if x.strip()]
    tpl_args = []
    for folder in folders:
        folder = str(folder).strip().replace("\\", "/").lstrip("/")
        if not folder or ".." in folder:
            continue
        # skip non-runnable dirs (profiles/workflows/helpers) to avoid
        # nuclei's "no templates found in path" fatal error
        if folder.split("/")[0] in NON_TEMPLATE_DIRS:
            continue
        full = (TEMPLATES_DIR / folder).resolve()
        if not _safe_under(str(full), [str(TEMPLATES_DIR)]):
            continue
        # a directory with zero runnable templates also aborts the scan
        if full.is_dir() and not any(
            fn.endswith((".yaml", ".yml"))
            for _dp, _dn, fns in os.walk(str(full))
            for fn in fns
        ):
            continue
        if full.exists():
            tpl_args.append(str(full))
    if tpl_args:
        for p in tpl_args:
            cmd += ["-t", p]
    elif TEMPLATES_DIR.is_dir():
        cmd += ["-t", str(TEMPLATES_DIR)]

    tags = body.get("tags") or []
    if isinstance(tags, str):
        tags = [x.strip() for x in tags.replace(",", " ").split() if x.strip()]
    tags = [t for t in tags if _safe_tag(t)]
    if tags:
        cmd += ["-tags", ",".join(tags)]

    etags = body.get("exclude_tags") or []
    if isinstance(etags, str):
        etags = [x.strip() for x in etags.replace(",", " ").split() if x.strip()]
    etags = [t for t in etags if _safe_tag(t)]
    if etags:
        cmd += ["-etags", ",".join(etags)]

    sevs = body.get("severity") or []
    if isinstance(sevs, str):
        sevs = [x.strip().lower() for x in sevs.split(",") if x.strip()]
    sevs = [s for s in sevs if s in SEVERITIES]
    if sevs and set(sevs) != set(SEVERITIES):
        cmd += ["-severity", ",".join(sevs)]

    opts = body.get("options") or {}
    rate = _int_opt(body, "rate_limit", int(opts.get("rate_limit") or 150), 1, 10000)
    conc = _int_opt(body, "concurrency", int(opts.get("concurrency") or 25), 1, 500)
    timeout = _int_opt(body, "timeout", int(opts.get("timeout") or 10), 1, 120)
    retries = _int_opt(body, "retries", int(opts.get("retries") or 1), 0, 10)
    cmd += ["-rate-limit", str(rate), "-c", str(conc), "-timeout", str(timeout), "-retries", str(retries)]

    if opts.get("headless") or body.get("headless"):
        cmd.append("-headless")
    if opts.get("automatic") or body.get("automatic"):
        cmd.append("-as")
    if opts.get("new_templates") or body.get("new_templates"):
        cmd.append("-nt")
    if opts.get("follow_redirects") or body.get("follow_redirects"):
        cmd.append("-fr")
    if opts.get("include_rr") or body.get("include_rr"):
        cmd.append("-irr")
    if opts.get("no_interactsh") or body.get("no_interactsh"):
        cmd.append("-ni")
    if opts.get("scan_all_ips") or body.get("scan_all_ips"):
        cmd.append("-sa")
    if opts.get("verbose") or body.get("verbose"):
        cmd.append("-v")

    label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
    return cmd, label, findings


def _follow_log(job_id, path, proc, stop_ev):
    pos = 0
    while not stop_ev.is_set():
        try:
            if Path(path).is_file():
                with open(path, "rb") as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        pos += len(chunk)
                        text = _strip_ansi(chunk.decode("utf-8", errors="replace"))
                        socketio.emit("job_log", {"id": job_id, "d": text})
        except Exception:
            pass
        if proc.poll() is not None:
            try:
                with open(path, "rb") as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        socketio.emit("job_log", {"id": job_id, "d": chunk.decode("utf-8", errors="replace")})
            except Exception:
                pass
            break
        stop_ev.wait(0.4)
    rc = proc.poll()
    with _jobs_lock:
        d, it = _job_get(job_id)
        if it:
            items = F.collect_job_dir(it.get("scan_dir"), job_id=job_id)
            # a user-initiated stop already set "stopped"; don't downgrade to failed
            if it.get("status") != "stopped":
                it["status"] = "done" if rc == 0 else "failed"
            it["exit_code"] = rc
            it["ended"] = int(time.time())
            it["findings_count"] = len(items)
            it["severities"] = F.summarize(items)["severities"]
            _jobs_save(d)
            final_status = it.get("status")
        else:
            final_status = "done" if rc == 0 else "failed"
    if rc != 0:
        # abnormal exit can leave nuclei's headless chrome orphaned
        _kill_leftover_chrome()
    if final_status == "stopped":
        pass  # _stop_job already emitted the "Scan stopped" notification
    else:
        nc_push(
            "Scan finished" if rc == 0 else "Scan failed",
            f"Job #{job_id} exit {rc}",
            "ok" if rc == 0 else "err",
        )
    socketio.emit("job_done", {"id": job_id, "exit_code": rc, "status": final_status})


def _start_job(body):
    targets = _parse_targets(body)
    with _jobs_lock:
        d = _jobs_load()
        running = [x for x in d["items"] if x.get("status") == "running"]
        if running:
            raise ValueError("A scan is already running. Stop it first.")
        jid = d.get("seq", 1)
        d["seq"] = jid + 1
        job_dir = SCANS_ROOT / f"job_{jid}"
        job_dir.mkdir(parents=True, exist_ok=True)
        log_path = str(LOGS_DIR / f"job_{jid}.log")
        cmd, target_label, findings = _build_cmd(body, job_dir, targets)
        item = {
            "id": jid,
            "target": target_label,
            "targets_n": len(targets),
            "tags": body.get("tags") or [],
            "severity": body.get("severity") or [],
            "folders": body.get("folders") or [],
            "cmd": cmd,
            "cmd_show": " ".join(shlex.quote(x) for x in cmd),
            "status": "running",
            "pid": None,
            "started": int(time.time()),
            "ended": None,
            "log": log_path,
            "scan_dir": str(job_dir),
            "findings_file": str(findings),
            "findings_count": 0,
        }
        d["items"].insert(0, item)
        _jobs_save(d)

    logf = open(log_path, "ab", buffering=0)
    logf.write(f"$ {' '.join(shlex.quote(x) for x in cmd)}\n\n".encode())
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(job_dir),
            stdout=logf,
            stderr=subprocess.STDOUT,
            env=_scan_env(),
            start_new_session=True,
        )
    except Exception as e:
        logf.close()
        with _jobs_lock:
            d, it = _job_get(jid)
            if it:
                it["status"] = "failed"
                it["ended"] = int(time.time())
                it["error"] = str(e)
                _jobs_save(d)
        raise
    with _jobs_lock:
        d, it = _job_get(jid)
        if it:
            it["pid"] = proc.pid
            _jobs_save(d)
    stop_ev = threading.Event()
    _followers[jid] = (stop_ev, proc, logf)
    t = threading.Thread(target=_follow_log, args=(jid, log_path, proc, stop_ev), daemon=True)
    t.start()
    nc_push("Scan started", f"Job #{jid} · {target_label}", "info")
    return item


def _kill_leftover_chrome():
    """Reap headless Chromium spawned by nuclei's -headless flag.

    nuclei launches chrome with --user-data-dir=/tmp/nuclei-<n>; those children
    call setsid so os.killpg on the nuclei group does not reach them. When a
    scan is stopped or dies abnormally they leak. Only one scan runs at a time
    (see _start_job), so sweeping every nuclei-owned chrome here is safe.
    """
    killed = 0
    proc_root = "/proc"
    if not os.path.isdir(proc_root):
        return killed
    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        try:
            with open(f"{proc_root}/{entry}/cmdline", "rb") as f:
                cl = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
        except Exception:
            continue
        if "user-data-dir=/tmp/nuclei-" in cl and "chrom" in cl.lower():
            try:
                os.kill(int(entry), signal.SIGKILL)
                killed += 1
            except Exception:
                pass
    return killed


def _kill_scan_procs(pid):
    """SIGTERM the scan process group, then hard-kill any leftover chrome."""
    if pid:
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        time.sleep(0.5)
        try:
            os.killpg(pid, signal.SIGKILL)
        except Exception:
            pass
    _kill_leftover_chrome()


def _stop_job(jid):
    with _jobs_lock:
        d, it = _job_get(jid)
        if not it:
            raise ValueError("Job not found")
        pid = it.get("pid")
        if it.get("status") != "running":
            return it
        it["status"] = "stopped"
        it["ended"] = int(time.time())
        _jobs_save(d)
    _kill_scan_procs(pid)
    pack = _followers.get(jid)
    if pack:
        pack[0].set()
    nc_push("Scan stopped", f"Job #{jid} stopped from the panel", "warn")
    return it


def _delete_job(jid):
    with _jobs_lock:
        d, it = _job_get(jid)
        if not it:
            raise ValueError("Job not found")
        running = it.get("status") == "running"
        log_path = it.get("log")
        scan_dir = it.get("scan_dir")
        pid = it.get("pid")
        d["items"] = [x for x in d["items"] if str(x.get("id")) != str(jid)]
        _jobs_save(d)
    if running and pid:
        _kill_scan_procs(pid)
    pack = _followers.pop(jid, None)
    if pack:
        pack[0].set()
    if log_path and os.path.isfile(log_path):
        try:
            os.unlink(log_path)
        except Exception:
            pass
    if scan_dir:
        safe = _safe_under(scan_dir, [str(SCANS_ROOT)])
        if safe and Path(safe).is_dir() and Path(safe) != Path(SCANS_ROOT).resolve():
            shutil.rmtree(safe, ignore_errors=True)
    return {"deleted": True}


def _job_items(it):
    path = it.get("findings_file")
    if path and os.path.isfile(path):
        return F.collect_file(path, job_id=it.get("id"))
    return F.collect_job_dir(it.get("scan_dir"), job_id=it.get("id"))


def _all_findings(limit_jobs=80):
    items = []
    jobs = _jobs_load()["items"][:limit_jobs]
    for it in jobs:
        items.extend(_job_items(it))
    return items


def _tpl_cache(force=False):
    now = time.time()
    if not force and TPL_CACHE.is_file():
        try:
            d = json.loads(TPL_CACHE.read_text(encoding="utf-8"))
            if now - float(d.get("ts") or 0) < 300:
                return d
        except Exception:
            pass
    dirs = []
    yaml_count = 0
    counts = {}
    if TEMPLATES_DIR.is_dir():
        for dirpath, dirnames, filenames in os.walk(TEMPLATES_DIR):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            rel = os.path.relpath(dirpath, TEMPLATES_DIR)
            if rel == ".":
                # do not descend into non-runnable dirs (profiles/workflows/helpers)
                dirnames[:] = [d for d in dirnames if d not in NON_TEMPLATE_DIRS]
                continue
            n = sum(1 for f in filenames if f.endswith((".yaml", ".yml")))
            yaml_count += n
            top = rel.split(os.sep)[0]
            counts[top] = counts.get(top, 0) + n
        dirs = [{"name": k, "count": counts[k]} for k in sorted(counts)]
    data = {
        "ts": now,
        "root": str(TEMPLATES_DIR),
        "ok": TEMPLATES_DIR.is_dir(),
        "dirs": dirs,
        "yaml_count": yaml_count,
        "tags": POPULAR_TAGS,
    }
    try:
        TPL_CACHE.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass
    return data


def _run_template_update():
    _tpl_update["running"] = True
    log_path = LOGS_DIR / "templates-update.log"
    try:
        with open(log_path, "ab", buffering=0) as logf:
            logf.write(b"$ nuclei -update-templates\n")
            cmd = [_nuclei_bin(), "-update-templates", "-ud", str(TEMPLATES_DIR), "-duc"]
            proc = subprocess.Popen(
                cmd, stdout=logf, stderr=subprocess.STDOUT, env=_scan_env(), start_new_session=True,
            )
            proc.wait(timeout=2400)
        _tpl_cache(True)
        nc_push("Templates updated", "nuclei -update-templates finished", "ok")
    except Exception as e:
        nc_push("Template update failed", str(e)[:200], "err")
    finally:
        _tpl_update["running"] = False


# ── health ───────────────────────────────────────────────────────────────────
_cpu_sample = None
_net_sample = None
_health_lock = threading.Lock()
_health_cache = {"t": 0.0, "data": None}


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024.0:
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f TB" % n


def _cpu_times():
    with open("/proc/stat") as f:
        parts = f.readline().split()
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return sum(nums), idle


def _net_bytes():
    rx = tx = 0
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if not name or name == "lo":
                continue
            cols = rest.split()
            if len(cols) < 10:
                continue
            rx += int(cols[0])
            tx += int(cols[8])
    return rx, tx


def _meminfo():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            info[k] = int(v.strip().split()[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(0, total - avail)
    pct = (used / total * 100.0) if total else 0.0
    return total, used, avail, pct


def _disk_root():
    st = os.statvfs("/")
    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = max(0, total - free)
    pct = (used / total * 100.0) if total else 0.0
    return total, used, free, pct


def _loadavg():
    with open("/proc/loadavg") as f:
        a, b, c = f.read().split()[:3]
    return float(a), float(b), float(c)


def _cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _uptime_sec():
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def _health_grade(pct):
    if pct >= 92:
        return "critical"
    if pct >= 78:
        return "warning"
    return "healthy"


def _health_collect():
    global _cpu_sample, _net_sample
    if not os.path.exists("/proc/stat"):
        return {
            "status": "healthy", "summary": "Host metrics need Linux /proc (panel is for Ubuntu VPS)",
            "took_ms": 0, "ts": int(time.time()), "hostname": os.environ.get("COMPUTERNAME") or "local",
            "uptime": 0, "cores": os.cpu_count() or 1, "cpu_model": "", "load": [0, 0, 0],
            "cpu_pct": 0, "cpu_status": "healthy",
            "ram": {"total": 0, "used": 0, "free": 0, "pct": 0, "status": "healthy", "total_h": "—", "used_h": "—"},
            "disk": {"total": 0, "used": 0, "free": 0, "pct": 0, "status": "healthy", "total_h": "—", "used_h": "—", "free_h": "—"},
            "net": {"in_bps": 0, "out_bps": 0, "in_h": "0 B/s", "out_h": "0 B/s", "rx_total_h": "0 B", "tx_total_h": "0 B", "status": "healthy"},
        }
    t0 = time.monotonic()
    total, idle = _cpu_times()
    rx, tx = _net_bytes()
    now = time.monotonic()
    cpu_pct = 0.0
    if _cpu_sample is None:
        time.sleep(0.04)
        total2, idle2 = _cpu_times()
        now = time.monotonic()
        dt, di = total2 - total, idle2 - idle
        cpu_pct = 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / float(dt))) * 100.0))
        _cpu_sample = (now, total2, idle2)
    else:
        pt, ptot, pidle = _cpu_sample
        dt, di = total - ptot, idle - pidle
        cpu_pct = 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / float(dt))) * 100.0))
        _cpu_sample = (now, total, idle)
    net_in_bps = net_out_bps = 0.0
    if _net_sample is not None:
        pt, prx, ptx = _net_sample
        dt = max(0.001, now - pt)
        net_in_bps = max(0.0, (rx - prx) / dt)
        net_out_bps = max(0.0, (tx - ptx) / dt)
    _net_sample = (now, rx, tx)
    mem_total, mem_used, mem_avail, mem_pct = _meminfo()
    disk_total, disk_used, disk_free, disk_pct = _disk_root()
    l1, l5, l15 = _loadavg()
    cores = os.cpu_count() or 1
    cpu_status = _health_grade(cpu_pct)
    ram_status = _health_grade(mem_pct)
    disk_status = _health_grade(disk_pct)
    net_busy = (net_in_bps + net_out_bps) > (50 * 1024 * 1024)
    net_status = "warning" if net_busy else "healthy"
    worst = "healthy"
    for s in (cpu_status, ram_status, disk_status, net_status):
        if s == "critical":
            worst = "critical"
        elif s == "warning" and worst != "critical":
            worst = "warning"
    if worst == "critical":
        summary = "System under pressure"
    elif worst == "warning":
        summary = "Some metrics are elevated"
    else:
        summary = "All systems nominal — everything is running smoothly"
    return {
        "status": worst,
        "summary": summary,
        "took_ms": round((time.monotonic() - t0) * 1000, 1),
        "ts": int(time.time()),
        "hostname": os.uname().nodename,
        "uptime": _uptime_sec(),
        "cores": cores,
        "cpu_model": _cpu_model(),
        "load": [round(l1, 2), round(l5, 2), round(l15, 2)],
        "cpu_pct": round(cpu_pct, 1),
        "cpu_status": cpu_status,
        "ram": {
            "total": mem_total, "used": mem_used, "free": mem_avail,
            "pct": round(mem_pct, 1), "status": ram_status,
            "total_h": _fmt_bytes(mem_total), "used_h": _fmt_bytes(mem_used),
        },
        "disk": {
            "total": disk_total, "used": disk_used, "free": disk_free,
            "pct": round(disk_pct, 1), "status": disk_status,
            "total_h": _fmt_bytes(disk_total), "used_h": _fmt_bytes(disk_used),
            "free_h": _fmt_bytes(disk_free),
        },
        "net": {
            "in_bps": round(net_in_bps), "out_bps": round(net_out_bps),
            "in_h": _fmt_bytes(net_in_bps) + "/s",
            "out_h": _fmt_bytes(net_out_bps) + "/s",
            "rx_total_h": _fmt_bytes(rx), "tx_total_h": _fmt_bytes(tx),
            "status": net_status,
        },
    }


def _fs_list(rel, root):
    base = Path(root).resolve()
    target = (base / rel).resolve() if rel else base
    safe = _safe_under(str(target), [str(base)])
    if not safe or not os.path.isdir(safe):
        return None
    items = []
    for child in sorted(Path(safe).iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        st = child.stat()
        items.append({
            "name": child.name,
            "dir": child.is_dir(),
            "size": 0 if child.is_dir() else st.st_size,
            "mtime": int(st.st_mtime),
        })
    crumbs = []
    cur = ""
    if rel:
        for part in Path(rel).parts:
            cur = f"{cur}/{part}".strip("/") if cur else part
            crumbs.append({"name": part, "path": cur})
    return {"root": str(base), "rel": rel, "items": items, "crumbs": crumbs}


# ── pages ────────────────────────────────────────────────────────────────────
@app.route("/favicon.ico")
def favicon():
    static = os.path.join(app.root_path, "static")
    ico = os.path.join(static, "favicon.svg")
    if os.path.isfile(ico):
        return send_from_directory(static, "favicon.svg", mimetype="image/svg+xml")
    return ("", 404)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        d = request.get_json(silent=True) or request.form
        if d.get("username") == PANEL_USER and d.get("password") == PANEL_PASS:
            session["ok"] = True
            session.permanent = True
            return jsonify(ok=True)
        return jsonify(error="ACCESS DENIED"), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@auth
def index():
    return render_template("index.html")


@app.route("/api/meta")
@auth
def api_meta():
    return jsonify(
        version=PANEL_VERSION,
        severities=SEVERITIES,
        tags=POPULAR_TAGS,
        engine=_engine_status(),
    )


@app.route("/api/dashboard")
@auth
def api_dashboard():
    eng = _engine_status()
    jobs = _jobs_load()["items"]
    running_jobs = [j for j in jobs if j.get("status") == "running"]
    health = _health_collect()
    findings_n = sum(int(j.get("findings_count") or 0) for j in jobs)
    return jsonify(
        engine=eng,
        running=running_jobs[0] if running_jobs else None,
        running_count=len(running_jobs),
        jobs_total=len(jobs),
        jobs_done=sum(1 for j in jobs if j.get("status") == "done"),
        jobs_failed=sum(1 for j in jobs if j.get("status") == "failed"),
        findings=findings_n,
        recent=jobs[:8],
        uptime=health["uptime"],
        hostname=health["hostname"],
        cpu_pct=health["cpu_pct"],
        ram=health["ram"],
        disk=health["disk"],
        version=eng.get("version"),
        ready=eng.get("ready"),
        state=eng.get("state"),
        yaml_count=eng.get("yaml_count"),
    )


@app.route("/api/health")
@auth
def api_health():
    now = time.monotonic()
    with _health_lock:
        if _health_cache["data"] is not None and (now - _health_cache["t"]) < 0.9:
            return jsonify(_health_cache["data"])
        data = _health_collect()
        _health_cache["t"] = time.monotonic()
        _health_cache["data"] = data
        return jsonify(data)


@app.route("/api/jobs", methods=["GET"])
@auth
def api_jobs():
    return jsonify(_jobs_load()["items"])


@app.route("/api/jobs", methods=["POST"])
@auth
def api_jobs_start():
    body = request.get_json(silent=True) or {}
    if not body.get("authorized"):
        return jsonify(error="Confirm you are authorized to test this target"), 400
    try:
        item = _start_job(body)
        return jsonify(ok=True, job=item)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/jobs/<int:jid>/stop", methods=["POST"])
@auth
def api_jobs_stop(jid):
    try:
        return jsonify(ok=True, job=_stop_job(jid))
    except ValueError as e:
        return jsonify(error=str(e)), 404


@app.route("/api/jobs/<int:jid>", methods=["DELETE"])
@auth
def api_jobs_delete(jid):
    try:
        return jsonify(ok=True, **_delete_job(jid))
    except ValueError as e:
        return jsonify(error=str(e)), 404


@app.route("/api/jobs/<int:jid>/log")
@auth
def api_jobs_log(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    path = it.get("log")
    text = ""
    if path and os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()[-200_000:]
        text = _strip_ansi(data.decode("utf-8", errors="replace"))
    return jsonify(id=jid, status=it.get("status"), log=text, job=it)


@app.route("/api/jobs/<int:jid>/findings")
@auth
def api_job_findings(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    items = _job_items(it)
    summary = F.summarize(items)
    cats = [
        {"id": "all", "title": "All findings", "icon": "fa-bug", "count": len(items), "cves": summary["cves"]},
    ]
    for t, n in (summary.get("types") or {}).items():
        cats.append({"id": "type:" + t, "title": t, "icon": "fa-layer-group", "count": n})
    return jsonify(
        job=it,
        domain=it.get("target") or "",
        path=it.get("scan_dir"),
        summary=summary,
        severities=summary["severities"],
        categories=cats,
    )


@app.route("/api/jobs/<int:jid>/findings/list")
@auth
def api_job_findings_list(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    items = _job_items(it)
    sev = request.args.get("severity")
    tag = request.args.get("tag")
    q = request.args.get("q")
    kind = request.args.get("type")
    if kind:
        items = [x for x in items if (x.get("type") or "") == kind]
    items = F.filter_items(items, severity=sev, tag=tag, q=q)
    return jsonify(kind="vulns", items=items[:2000], total=len(items))


@app.route("/api/jobs/<int:jid>/export")
@auth
def api_job_export(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    items = F.filter_items(_job_items(it), severity=request.args.get("severity"))
    fmt = (request.args.get("fmt") or "html").lower()
    title = f"Nuclei job #{jid} — {it.get('target') or ''}"
    if fmt == "md":
        body = F.export_md(items, title)
        return Response(body, mimetype="text/markdown", headers={
            "Content-Disposition": f"attachment; filename=nuclei-job-{jid}.md"
        })
    body = F.export_html(items, title)
    return Response(body, mimetype="text/html", headers={
        "Content-Disposition": f"attachment; filename=nuclei-job-{jid}.html"
    })


@app.route("/api/findings")
@auth
def api_findings_all():
    items = _all_findings()
    sev = request.args.get("severity")
    q = request.args.get("q")
    filtered = F.filter_items(items, severity=sev, q=q)
    summary = F.summarize(items)
    return jsonify(summary=summary, severities=summary["severities"], items=filtered[:2000], total=len(filtered))


@app.route("/api/findings/export")
@auth
def api_findings_export():
    items = F.filter_items(_all_findings(), severity=request.args.get("severity"), q=request.args.get("q"))
    fmt = (request.args.get("fmt") or "html").lower()
    title = "Nuclei findings"
    if fmt == "md":
        return Response(F.export_md(items, title), mimetype="text/markdown", headers={
            "Content-Disposition": "attachment; filename=nuclei-findings.md"
        })
    return Response(F.export_html(items, title), mimetype="text/html", headers={
        "Content-Disposition": "attachment; filename=nuclei-findings.html"
    })


@app.route("/api/templates")
@auth
def api_templates():
    force = request.args.get("refresh") in ("1", "true")
    d = _tpl_cache(force)
    d["updating"] = bool(_tpl_update.get("running"))
    d["version"] = _nuclei_version()
    log = ""
    lp = LOGS_DIR / "templates-update.log"
    if lp.is_file():
        with open(lp, "rb") as f:
            log = _strip_ansi(f.read()[-20_000:].decode("utf-8", errors="replace"))
    d["log"] = log
    return jsonify(d)


@app.route("/api/templates/tree")
@auth
def api_templates_tree():
    rel = (request.args.get("path") or "").replace("\\", "/").lstrip("/")
    if ".." in rel:
        return jsonify(error="bad path"), 400
    listing = _fs_list(rel, TEMPLATES_DIR)
    if listing is None:
        return jsonify(error="not found"), 404
    return jsonify(listing)


@app.route("/api/templates/update", methods=["POST"])
@auth
def api_templates_update():
    if not _nuclei_ready():
        return jsonify(error="nuclei is not installed"), 400
    if _tpl_update.get("running"):
        return jsonify(ok=True, already=True)
    t = threading.Thread(target=_run_template_update, daemon=True)
    t.start()
    nc_push("Updating templates", "nuclei -update-templates started", "info")
    return jsonify(ok=True)


@app.route("/api/secrets", methods=["GET"])
@auth
def api_secrets_get():
    d = _pdcp_load()
    key = d.get("api_key") or ""
    masked = (("•" * max(0, len(key) - 4)) + key[-4:]) if key else ""
    resp = dict(pdcp_set=bool(key), pdcp_masked=masked)
    # only hand back the plaintext when the eye toggle explicitly asks for it
    if request.args.get("reveal") in ("1", "true"):
        resp["pdcp_key"] = key
    return jsonify(resp)


@app.route("/api/secrets", methods=["POST"])
@auth
def api_secrets_set():
    body = request.get_json(silent=True) or {}
    key = str(body.get("pdcp") or body.get("api_key") or "").strip()
    if key and len(key) > 200:
        return jsonify(error="Key looks too long"), 400
    _pdcp_save({"api_key": key})
    return jsonify(ok=True)


@app.route("/api/fs")
@auth
def api_fs():
    kind = (request.args.get("root") or "scans").lower()
    rel = (request.args.get("path") or "").replace("\\", "/").lstrip("/")
    if ".." in rel:
        return jsonify(error="bad path"), 400
    root = SCANS_ROOT if kind != "templates" else TEMPLATES_DIR
    listing = _fs_list(rel, root)
    if listing is None:
        return jsonify(error="not found"), 404
    listing["kind"] = kind
    return jsonify(listing)


@app.route("/api/fs/download")
@auth
def api_fs_download():
    kind = (request.args.get("root") or "scans").lower()
    rel = (request.args.get("path") or "").replace("\\", "/").lstrip("/")
    if ".." in rel or not rel:
        return jsonify(error="bad path"), 400
    root = SCANS_ROOT if kind != "templates" else TEMPLATES_DIR
    full = _safe_under(str(Path(root) / rel), [str(root)])
    if not full or not os.path.isfile(full):
        return jsonify(error="not found"), 404
    return send_file(full, as_attachment=True)


@app.route("/api/nc")
@auth
def api_nc():
    d = _nc_load()
    items = d.get("items") or []
    unread = sum(1 for x in items if not x.get("read"))
    return jsonify(items=items[:80], unread=unread)


@app.route("/api/nc/read", methods=["POST"])
@auth
def api_nc_read():
    body = request.get_json(silent=True) or {}
    with _nc_lock:
        d = _nc_load()
        if body.get("all"):
            for it in d.get("items") or []:
                it["read"] = True
        else:
            nid = body.get("id")
            for it in d.get("items") or []:
                if it.get("id") == nid:
                    it["read"] = True
        _nc_save(d)
    return jsonify(ok=True)


@app.route("/api/nc/clear", methods=["POST"])
@auth
def api_nc_clear():
    with _nc_lock:
        d = _nc_load()
        d["items"] = [x for x in (d.get("items") or []) if not x.get("read")]
        _nc_save(d)
    return jsonify(ok=True)


def _svc_ok(name):
    return bool(re.match(r"^[a-zA-Z0-9_@.-]+$", name or ""))


@app.route("/api/services")
@auth
def api_services():
    names = ["nuclei-panel"]
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            text=True, timeout=8,
        )
        for line in out.splitlines():
            unit = line.split()[0] if line.split() else ""
            if "nuclei" in unit and unit.endswith(".service"):
                n = unit.replace(".service", "")
                if n not in names:
                    names.append(n)
    except Exception:
        pass
    items = []
    for n in names:
        try:
            show = subprocess.check_output(
                ["systemctl", "show", n, "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "Description", "-p", "FragmentPath"],
                text=True, timeout=5,
            )
            info = dict(ln.split("=", 1) for ln in show.splitlines() if "=" in ln)
        except Exception:
            info = {}
        items.append({
            "name": n,
            "active": info.get("ActiveState", "unknown"),
            "sub": info.get("SubState", ""),
            "pid": info.get("MainPID", "0"),
            "desc": info.get("Description", n),
            "path": info.get("FragmentPath", ""),
        })
    return jsonify(items)


@app.route("/api/services/<name>/<action>", methods=["POST"])
@auth
def api_services_action(name, action):
    if not _svc_ok(name) or action not in ("start", "stop", "restart"):
        return jsonify(error="bad request"), 400
    if name == "nuclei-panel" and action == "stop":
        return jsonify(error="Stopping the panel from itself would lock you out"), 400
    try:
        subprocess.check_call(["systemctl", action, name], timeout=20)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/services/<name>/logs")
@auth
def api_services_logs(name):
    if not _svc_ok(name):
        return jsonify(error="bad name"), 400
    try:
        out = subprocess.check_output(
            ["journalctl", "-u", name, "-n", "200", "--no-pager", "-o", "short-iso"],
            text=True, timeout=10,
        )
        return jsonify(log=out)
    except Exception as e:
        return jsonify(error=str(e)), 500


@socketio.on("connect")
def ws_connect():
    if not session.get("ok"):
        return False


@socketio.on("job_follow")
def ws_job_follow(data):
    if not session.get("ok"):
        return
    jid = (data or {}).get("id")
    _, it = _job_get(jid)
    if not it:
        return
    path = it.get("log")
    if path and os.path.isfile(path):
        with open(path, "rb") as f:
            text = f.read()[-80_000:].decode("utf-8", errors="replace")
        emit("job_log", {"id": it["id"], "d": text, "reset": True})


class _PidWatch:
    def __init__(self, pid):
        self.pid = int(pid)

    def poll(self):
        try:
            os.kill(self.pid, 0)
            return None
        except OSError:
            return 0


def _recover_running_jobs():
    with _jobs_lock:
        items = list((_jobs_load().get("items") or []))
    for it in items:
        if it.get("status") != "running":
            continue
        jid = it.get("id")
        pid = it.get("pid")
        log_path = it.get("log")
        if not pid:
            continue
        try:
            os.kill(int(pid), 0)
        except OSError:
            with _jobs_lock:
                d, cur = _job_get(jid)
                if cur and cur.get("status") == "running":
                    cur["status"] = "failed"
                    cur["ended"] = int(time.time())
                    cur["error"] = "scan process gone after panel restart"
                    _jobs_save(d)
            _kill_leftover_chrome()
            continue
        if jid in _followers:
            continue
        stop_ev = threading.Event()
        watch = _PidWatch(pid)
        _followers[jid] = (stop_ev, watch, None)
        t = threading.Thread(target=_follow_log, args=(jid, log_path, watch, stop_ev), daemon=True)
        t.start()
        print(f"[*] reattached running job #{jid} pid={pid}")


if __name__ == "__main__":
    print(f"\n[*] Nuclei Control Panel v{PANEL_VERSION}")
    print(f"[*] http://0.0.0.0:{PANEL_PORT}\n")
    _recover_running_jobs()
    socketio.run(app, host=PANEL_HOST, port=PANEL_PORT, allow_unsafe_werkzeug=True)
