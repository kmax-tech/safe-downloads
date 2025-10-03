# Standard library imports
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, Tuple, Optional
import requests


# VirusTotal API key (set in environment)
VT_API_KEY = os.environ.get("VT_API_KEY", "")

# Maximum file size for uploads (32MB)
MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # 32MB


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_lookup_by_hash(sha256: str) -> Tuple[str, Dict]:
    """
    Try to fetch an existing VT file object by SHA-256.
    Returns: ("found", json) | ("not_found", {}) | ("error", {"error": str, "detail": str})
    """
    if not VT_API_KEY:
        return "error", {"error": "Missing VT_API_KEY", "detail": ""}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=30)
    except Exception as e:
        return "error", {"error": f"Lookup request failed: {e}", "detail": ""}

    if r.status_code == 404:
        return "not_found", {}
    if r.status_code == 429:
        return "error", {
            "error": "Rate limited by VirusTotal (HTTP 429).",
            "detail": r.text[:300],
        }
    try:
        r.raise_for_status()
    except Exception as e:
        return "error", {"error": f"Lookup error: {e}", "detail": r.text[:300]}

    return "found", r.json()


def vt_upload_file(p: Path) -> Tuple[bool, str]:
    """
    Upload a file to VirusTotal for scanning.
    Returns (True, analysis_id) on success, (False, error_message) on failure.
    """
    if not VT_API_KEY:
        return False, "Missing VT_API_KEY"
    if p.stat().st_size > MAX_UPLOAD_BYTES:
        return False, f"File too large (> {MAX_UPLOAD_BYTES} bytes)"
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with p.open("rb") as f:
        files = {"file": (p.name, f)}
        r = requests.post(url, headers=headers, files=files, timeout=120)
    try:
        r.raise_for_status()
    except Exception as e:
        return False, f"Upload error: {e} | {r.text[:300]}"
    data = r.json()
    analysis_id = data.get("data", {}).get("id")
    return (True, analysis_id) if analysis_id else (False, "No analysis id returned")


def vt_poll_analysis(
    analysis_id: str, timeout_s: int = 90, interval_s: float = 1.5
) -> Dict:
    """
    Poll VirusTotal for the result of a file analysis.
    Waits until the analysis is complete or times out.
    Returns the analysis JSON or an error dict.
    """
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    start = time.time()
    while True:
        r = requests.get(url, headers=headers, timeout=30)
        try:
            r.raise_for_status()
        except Exception:
            return {"error": f"Analysis fetch failed: {r.text[:300]}"}
        data = r.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        if time.time() - start > timeout_s:
            return {"error": "Timed out waiting for VT analysis", "data": data}
        time.sleep(interval_s)


def _extract_stats(obj: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Normalize stats from either:
      - analysis object: data.attributes.stats
      - file object: data.attributes.last_analysis_stats
    Returns (stats_dict | None, status_text | None)
    """
    attrs = (obj or {}).get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("stats") or attrs.get("last_analysis_stats")
    status = attrs.get("status") or attrs.get("last_analysis_results") and "completed"
    return stats or None, status


def vt_is_clean(
    analysis_or_file_json: Dict, threshold: float = 0.9
) -> Tuple[bool, Dict]:
    """
    Decide if a file is clean based on majority voting.
    threshold: fraction of engines that must consider the file harmless/undetected.
    """
    stats, status = _extract_stats(analysis_or_file_json)
    stats = stats or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    total = malicious + suspicious + harmless + undetected
    safe_votes = harmless + undetected
    ratio = safe_votes / total if total > 0 else 0

    details = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "status": status or "unknown",
        "ratio_safe": ratio,
        "total_engines": total,
    }

    return ratio >= threshold, details


# @app.route("/download-zip")
# def download_zip():
#     tokens = session.get("allowed_downloads", [])
#     if not tokens:
#         abort(403)

#     sid = _get_or_create_session_id()
#     mapping = SERVER_DOWNLOAD_STORE.get(sid, {})

#     mem = io.BytesIO()
#     with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
#         for t in tokens:
#             ap = mapping.get(t)
#             if not ap:
#                 continue
#             fp = Path(ap)
#             if fp.exists() and fp.is_file() and within_base_dir(fp):
#                 zf.write(fp, arcname=fp.name)
#     mem.seek(0)
#     return send_file(mem, as_attachment=True, download_name="clean_files.zip", mimetype="application/zip")


# # ---------- Small server-side partial templates ----------

# # HTML toolbar partial for showing download ZIP button
# _TOOLBAR_TEMPLATE = """
# <div id=\"toolbar\" class=\"toolbar\">
#     <a href=\"{{ url_for('index') }}\">Back to file list</a>
#     {% if clean_count > 0 %}
#         <a class=\"zip-btn\" href=\"{{ url_for('download_zip') }}\">Download all clean as ZIP ({{ clean_count }})</a>
#     {% else %}
#         <span class=\"muted\">No clean files yet</span>
#     {% endif %}
# </div>
# """

# # A lightweight toolbar that refreshes to show "Download all clean as ZIP" when any are available
# @app.route("/toolbar", methods=["GET"])
# def toolbar():
#     """
#     Toolbar partial: Shows download ZIP button if any clean files are available.
#     """
#     allowed = session.get("allowed_downloads", {})
#     count = len(allowed)
#     return render_template_string(_TOOLBAR_TEMPLATE, clean_count=count)
