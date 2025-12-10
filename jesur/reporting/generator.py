"""
JESUR - Enhanced SMB Share Scanner
Report generator module - HTML report generation

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import os
import jinja2
from datetime import datetime
from collections import Counter, defaultdict
from jesur.utils.common import normalize_smb_path

def save_results(all_files, sensitive_results, base_filename, scan_args, stats=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    formatted_timestamp = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    
    # Locate template
    template_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'templates')
    template_file = 'report.html'
    
    if not os.path.exists(os.path.join(template_dir, template_file)):
        from jesur.utils.logger import log_error
        log_error(f"Template file not found: {os.path.join(template_dir, template_file)}")
        return None, None

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
    template = env.get_template(template_file)
    
    stats = stats or {}
    
    # Create reports directory if it doesn't exist
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    
    # --- FILES REPORT ---
    files_report = os.path.join(reports_dir, f"{base_filename}_files_{timestamp}.html")
    
    files_by_ip = defaultdict(list)
    for file_info in all_files:
        ip = file_info.get('ip', 'unknown')
        file_info['path'] = normalize_smb_path(file_info.get('path', ''))
        files_by_ip[ip].append(file_info)
    
    # --- SENSITIVE REPORT ---
    sensitive_report = os.path.join(reports_dir, f"{base_filename}_sensitive_{timestamp}.html")
    
    results_by_ip = defaultdict(lambda: defaultdict(list))
    category_counts = Counter()
    for result in sensitive_results:
        ip = result.get('ip', 'unknown')
        share = result.get('share', 'unknown')
        result['path'] = normalize_smb_path(result.get('path', ''))
        results_by_ip[ip][share].append(result)
        category_counts[result.get('category', 'Unknown')] += 1
    
    # Build chart data
    files_per_ip = {ip: len(entries) for ip, entries in files_by_ip.items()}
    chart_data = {
        'categories': list(category_counts.keys()),
        'category_counts': list(category_counts.values()),
        'files_ips': list(files_per_ip.keys()),
        'files_counts': list(files_per_ip.values()),
        'totals': {
            'files': len(all_files),
            'sensitive': len(sensitive_results),
            'hosts_scanned': stats.get('hosts_scanned', 0),
            'shares_found': stats.get('shares_found', 0),
            'readable_shares': stats.get('readable_shares', 0),
            'writable_shares': stats.get('writable_shares', 0),
        }
    }
    
    files_html = template.render(
        title="Jesur - Accessed Files Report",
        timestamp=formatted_timestamp,
        network=scan_args.network if hasattr(scan_args, 'network') else 'N/A',
        username=scan_args.username,
        domain=scan_args.domain,
        content_type='files',
        files=files_by_ip,
        results=results_by_ip,
        stats=stats,
        chart_data=chart_data
    )
    
    with open(files_report, 'w', encoding='utf-8') as f:
        f.write(files_html)
    
    sensitive_html = template.render(
        title="Jesur - Sensitive Content Report",
        timestamp=formatted_timestamp,
        network=scan_args.network if hasattr(scan_args, 'network') else 'N/A',
        username=scan_args.username,
        domain=scan_args.domain,
        content_type='sensitive',
        files=files_by_ip,
        results=results_by_ip,
        stats=stats,
        chart_data=chart_data
    )
    
    with open(sensitive_report, 'w', encoding='utf-8') as f:
        f.write(sensitive_html)
    
    return files_report, sensitive_report
