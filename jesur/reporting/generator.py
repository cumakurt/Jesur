import os
import shutil
import jinja2
from datetime import datetime
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from jesur.utils.common import normalize_smb_path


def _resolve_logo_source_path() -> Optional[str]:
    """
    Prefer repo-root jesur_logo.png (next to the jesur package), then packaged data asset.
    """
    reporting_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.normpath(os.path.join(reporting_dir, "..", "..", "jesur_logo.png")),
        os.path.normpath(os.path.join(reporting_dir, "..", "data", "jesur_logo.png")),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _human_bytes(n: Any) -> str:
    if n is None or n == 0:
        return "0 B"
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} PB"


def _render_fallback_html(
    *,
    formatted_timestamp: str,
    scan_args: Any,
    all_files: List[Dict[str, Any]],
    sensitive_results: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> str:
    """Render a minimal built-in report if template assets are missing."""
    lines = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>JESUR Report</title></head><body>",
        '<img src="jesur_logo.png" class="brand-logo" alt="JESUR logo" />',
        "<h1>JESUR Scan Report</h1>",
        f"<p><strong>Generated:</strong> {formatted_timestamp}</p>",
        f"<p><strong>Network:</strong> {getattr(scan_args, 'network', 'N/A')}</p>",
        f"<p><strong>User:</strong> {getattr(scan_args, 'username', 'N/A')}@{getattr(scan_args, 'domain', 'N/A')}</p>",
        "<h2>Summary</h2>",
        "<ul>",
        f"<li>Hosts scanned: {stats.get('hosts_scanned', 0)}</li>",
        f"<li>Shares found: {stats.get('shares_found', 0)}</li>",
        f"<li>Files scanned: {len(all_files)}</li>",
        f"<li>Sensitive findings: {len(sensitive_results)}</li>",
        "</ul>",
        "<h2>Accessed files</h2>",
        "<h2>Sensitive content</h2>",
        "<div id='filter-category-sensitive'></div>",
        "<div id='pagination-sensitive'></div>",
        "<button id='back-to-top'>Top</button>",
        "<script>",
        "const chartCategories = [];",
        "</script>",
        "</body></html>",
    ]
    return "\n".join(lines)


def save_results(
    all_files: List[Dict[str, Any]],
    sensitive_results: List[Dict[str, Any]],
    base_filename: str,
    scan_args: Any,
    stats: Optional[Dict[str, Any]] = None,
    reports_dir: str = ".",
    download_href_prefix: str = "out_download/",
) -> Tuple[Optional[str], Optional[str]]:
    """
    Write a single unified HTML report (Material / Google-style dashboard).

    Returns (report_path, None) for backward compatibility with callers expecting a tuple.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    formatted_timestamp = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    template_dir = os.path.join(os.path.dirname(__file__), "..", "data", "templates")
    template_file = "report.html"

    template_path = os.path.join(template_dir, template_file)
    template_exists = os.path.exists(template_path)

    os.makedirs(reports_dir, exist_ok=True)

    template = None
    if template_exists:
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )
        template = env.get_template(template_file)
    else:
        from jesur.utils.logger import log_warning
        log_warning(f"Template file not found, using fallback HTML: {template_path}")

    stats = stats or {}

    files_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for file_info in all_files:
        ip = file_info.get("ip", "unknown")
        file_info["path"] = normalize_smb_path(file_info.get("path", ""))
        files_by_ip[ip].append(file_info)

    results_by_ip: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    category_counts: Counter = Counter()
    for result in sensitive_results:
        ip = result.get("ip", "unknown")
        share = result.get("share", "unknown")
        result["path"] = normalize_smb_path(result.get("path", ""))
        results_by_ip[ip][share].append(result)
        category_counts[result.get("category", "Unknown")] += 1

    files_per_ip = {ip: len(entries) for ip, entries in files_by_ip.items()}
    chart_data = {
        "categories": list(category_counts.keys()),
        "category_counts": list(category_counts.values()),
        "files_ips": list(files_per_ip.keys()),
        "files_counts": list(files_per_ip.values()),
        "totals": {
            "files": len(all_files),
            "sensitive": len(sensitive_results),
            "hosts_scanned": stats.get("hosts_scanned", 0),
            "shares_found": stats.get("shares_found", 0),
            "readable_shares": stats.get("readable_shares", 0),
            "writable_shares": stats.get("writable_shares", 0),
        },
    }

    duration_s = 0.0
    if stats.get("start_time") and stats.get("end_time"):
        try:
            duration_s = float(stats["end_time"]) - float(stats["start_time"])
        except (TypeError, ValueError):
            duration_s = 0.0

    stats_display = {
        "bytes_read_human": _human_bytes(stats.get("bytes_read", 0)),
        "duration_human": f"{duration_s:.1f}s" if duration_s else "—",
    }

    report_path = os.path.join(reports_dir, f"{base_filename}_report_{timestamp}.html")
    report_dir = os.path.dirname(os.path.abspath(report_path))

    logo_href: Optional[str] = None
    logo_src = _resolve_logo_source_path()
    if logo_src:
        try:
            shutil.copy2(logo_src, os.path.join(report_dir, "jesur_logo.png"))
            logo_href = "jesur_logo.png"
        except OSError:
            logo_href = None

    if template is not None:
        html = template.render(
            title="JESUR — Scan Report",
            timestamp=formatted_timestamp,
            network=scan_args.network if hasattr(scan_args, "network") else "N/A",
            username=scan_args.username,
            domain=scan_args.domain,
            files=files_by_ip,
            results=results_by_ip,
            stats=stats,
            stats_display=stats_display,
            chart_data=chart_data,
            download_href_prefix=download_href_prefix,
            page_size=100,
            logo_href=logo_href,
        )
    else:
        html = _render_fallback_html(
            formatted_timestamp=formatted_timestamp,
            scan_args=scan_args,
            all_files=all_files,
            sensitive_results=sensitive_results,
            stats=stats,
        )
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return report_path, None
