# Standard library imports
import os
from pathlib import Path
from typing import List, Optional, Any
from threading import RLock
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import (
    Blueprint,
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    send_file,
    abort,
    flash,
)

from werkzeug.utils import secure_filename
import dotenv
import re
import vt_helper as vt

dotenv.load_dotenv()


# -------------------- Dataclasses --------------------
@dataclass
class VirusTotalEntry:
    sha: str
    verdict_clean: bool
    processed: bool
    details: dict
    scanned_at: datetime


@dataclass
class ScanRecord:
    id: str
    name: str
    path: Path
    message: str
    scan: Optional[VirusTotalEntry]  # VT stats, status, etc.


# -------------------- GLOBALS --------------------

ALPHABET = string.ascii_letters + string.digits
# Global Dictionaries, contain mappings for ids and files

# id -> ScanRecord
GLOBAL_SCAN_DICT: dict[str, ScanRecord] = {}
PATH_ID_DICT: dict[Path, str] = {}

FILE_INFO_LOCK = RLock()


# -------------------- CONFIG --------------------
# Directory where files are stored and scanned
BASE_DIR = os.environ.get("SAFE_FILES_DIR", "./shared_quarantine")

# Flask secret key for session management
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-prod")

# Optional: allow overriding the whole base URL via env, else construct from host + port
WEB_BROWSER_BASE_URL = os.getenv(
    "WEB_BROWSER_BASE_URL"
)  # e.g. "https://example.com/web"
WEB_BROWSER_PORT = os.getenv("WEB_BROWSER_PORT", "3003")  # default


# -------------------- APP --------------------


bp = Blueprint("main", __name__,
               template_folder="templates",
               static_folder="static",
               static_url_path="/static")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,  # Trust X-Forwarded-For (client IP)
    x_proto=1,  # Trust X-Forwarded-Proto (http/https)
    x_host=1,  # Trust X-Forwarded-Host (original Host header)
    x_port=1,  # Trust X-Forwarded-Port (original port)
)


# ---------- Helpers ----------


@bp.get("/healthz")
def healthz():
    return "ok", 200


def get_ScanRecord_by_id(id: str) -> Optional[ScanRecord]:
    with FILE_INFO_LOCK:
        entry = GLOBAL_SCAN_DICT.get(id, None)
        return entry


def delete_ScanRecord_by_id(id: str) -> Optional[ScanRecord]:
    with FILE_INFO_LOCK:
        entry = GLOBAL_SCAN_DICT.pop(id, None)  # return None if id not found
        if entry:
            PATH_ID_DICT.pop(entry.path)
        return entry


def create_scan_record_entry(p: Path) -> ScanRecord:
    random_id = "".join(secrets.choice(ALPHABET) for _ in range(16))  # 16-char ID

    scanr_record = ScanRecord(
        id=random_id,
        name=p.name,
        path=p,
        message="",
        scan=None,
    )
    return scanr_record


def put_entry_scan_record(id: str, field: str, value: Any):
    with FILE_INFO_LOCK:
        scan_record = GLOBAL_SCAN_DICT.get(id)
        if scan_record is None:
            return None

        if not hasattr(scan_record, field):
            raise AttributeError(f"{field} is not a valid attribute of ScanRecord")

        setattr(scan_record, field, value)
        return scan_record


def control_file_status(p: Path) -> Optional[ScanRecord]:
    with FILE_INFO_LOCK:
        if p not in PATH_ID_DICT:
            entry = create_scan_record_entry(p)
            PATH_ID_DICT[p] = entry.id
            GLOBAL_SCAN_DICT[entry.id] = entry
            return entry
        id = PATH_ID_DICT[p]
        entry = GLOBAL_SCAN_DICT.get(id)
        if entry and entry.scan:
            sha = vt.file_sha256(p)
            if sha != entry.scan.sha:
                entry.scan = None
        return entry



def get_or_perform_scan(id: str) -> "ScanRecord|None":
    """
    Return the updated ScanRecord or None if the record ID doesn't exist.

    - Uses cache by token.
    - Looks up by SHA-256 in VT first.
    - If not found, uploads and polls until analysis completes (or times out).
    """
    message = ""
    scan_record = get_ScanRecord_by_id(id)
    if not scan_record:
        return None

    if scan_record.scan:
        return scan_record

    p = scan_record.path
    if not p.exists():
        message = f"File not found: {p}"
        scan_record = put_entry_scan_record(id, "message", message)
        return scan_record

    # 1) Compute SHA-256 and try VT hash lookup first
    sha = vt.file_sha256(p)
    status, lookup_json = vt.vt_lookup_by_hash(sha)

    if status == "found":
        clean, details = vt.vt_is_clean(lookup_json)
        entry = VirusTotalEntry(
            sha=sha,
            verdict_clean=clean,
            processed=True,
            details=details,
            scanned_at=datetime.now(timezone.utc),
        )
        return put_entry_scan_record(id, "scan", entry)

    if status == "error":
        message = f"Hash lookup failed: {lookup_json.get('error')}. {lookup_json.get('detail','')}"
        return put_entry_scan_record(id, "message", message)

    # 2) Not found -> upload and poll
    ok, analysis_id_or_err = vt.vt_upload_file(p)
    if not ok:
        message = f"Problem with upload: {analysis_id_or_err}"
        return put_entry_scan_record(id, "message", message)

    analysis_json_or_err = vt.vt_poll_analysis(analysis_id_or_err)
    clean, details = vt.vt_is_clean(analysis_json_or_err)

    entry = VirusTotalEntry(
        sha=sha,
        verdict_clean=clean,
        processed=True,
        details=details,
        scanned_at=datetime.now(timezone.utc),
    )
    return put_entry_scan_record(id, "scan", entry)


def within_base_dir(path: Path) -> bool:
    base = Path(BASE_DIR).resolve()
    try:
        resolved = path.resolve(strict=True)
        if resolved.is_symlink():
            return False
        resolved.relative_to(base)
        return True
    except (FileNotFoundError, ValueError):
        return False


def get_file_information() -> List[ScanRecord]:
    base = Path(BASE_DIR).resolve()
    base.mkdir(parents=True, exist_ok=True)
    records = []
    for p in sorted(base.iterdir()):
        if p.is_symlink():         # avoid following symlinks
            continue
        if p.is_file():
            rec = control_file_status(p.resolve())
            if rec:
                records.append(rec)
    return records


def delete_files_in_base(filenames_id: list[str]) -> int:
    deleted = 0

    for id in filenames_id:
        scan_record = get_ScanRecord_by_id(id)
        if not scan_record:
            print(f"Failed to find candidate {id}")
            continue

        candidate = scan_record.path
        # Strong safety check
        if not within_base_dir(candidate):
            print(f"Skipping {scan_record.name}: outside base directory")
            continue

        try:
            candidate.unlink()
            delete_ScanRecord_by_id(id)  
            deleted += 1
        except OSError as e:
            print(f"Failed to delete {candidate}: {e}")

    return deleted


# ---------- Routes ----------
@bp.route("/", methods=["GET"])
def index():
    """
    Home page: List all files available for scanning in the base directory.
    """
    scan_status_list = get_file_information()

    return render_template(
        "index.html",
        scan_record_list=scan_status_list,
        base_dir=Path(BASE_DIR).resolve().name,
    )


# Use of url_for so endpoint stays same, even if function is changing
@bp.route("/start-scan", methods=["POST"])
def start_scan():
    """
    Start a scan for selected files. Only selected files get scanned/rendered.
    """

    # Get selected names from the form, sanitize them, and keep only those we know about
    selected_id = [secure_filename(id) for id in request.form.getlist("files")]
    scan_record_list = [get_ScanRecord_by_id(id) for id in selected_id]
    scan_record_list = [
        r for r in scan_record_list if r is not None
    ]  # kick outn one entries

    if not scan_record_list:
        flash("Please select at least one file.")
        return redirect(url_for("main.index"))

    # Render a page with placeholder rows; each row self-triggers an HTMX POST to /scan-one
    return render_template(
        "results.html",
        scan_record_list=scan_record_list,
    )


@bp.route("/scan-one", methods=["POST"])
def scan_one():
    """
    Scan exactly one file and return a single <tr> ready to drop into the table.
    Handles VirusTotal upload, polling, and session marking for clean files.
    """
    id = request.form.get("id")
    if not id:
        return {"error": "Missing id"}, 400

    id = secure_filename(id)

    scan_record = get_or_perform_scan(id)

    return render_template("partials/scan_result.html", scan_record=scan_record)


def safe_filename(filename: str, replacement: str = "_") -> str:
    """
    Convert a filename into a safe version by:
    - Removing/ replacing special characters
    - Avoiding spaces
    """
    # Replace any character that is not alphanumeric, dash, or underscore
    safe_name = re.sub(r"[^A-Za-z0-9._-]", replacement, filename)

    # Prevent accidental empty name
    if not safe_name:
        safe_name = "file"

    return safe_name


@bp.route("/download")
def download():
    h = request.args.get("h", "")
    if not h:
        abort(400)

    scan_record = GLOBAL_SCAN_DICT.get(h)
    if not scan_record or not scan_record.scan:
        abort(403)

    fp = scan_record.path
    if fp.exists() and fp.is_file() and scan_record.scan.verdict_clean:
        return send_file(fp, as_attachment=True, download_name=safe_filename(fp.name))
    abort(404)


@bp.route("/delete_files", methods=["POST"])
def delete_files():
    selected_ids = request.form.getlist("files")
    if not selected_ids:
        flash("No files selected to delete.")
        return redirect(url_for("main.index"))

    delete_files_in_base(selected_ids)
    return redirect(url_for("main.index"))




def _browser_service_url():
    if WEB_BROWSER_BASE_URL:
        # Always normalize with a trailing slash
        return WEB_BROWSER_BASE_URL.rstrip("/") + "/"
    return "/"  # or fallback you want (e.g. root)
    

@bp.context_processor
def inject_browser_service_url():
    return {"web_service_url": _browser_service_url()}


# 👇 mount everything under /app
app.register_blueprint(bp, url_prefix="/app")

print("=== URL MAP ===")
print(app.url_map)
print("================")


# Entry point for running the Flask app
if __name__ == "__main__":
    # Ensure base directory exists before starting
    Path(BASE_DIR).mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
