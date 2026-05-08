import json
import csv
import os
from datetime import datetime


def _duration_seconds(stats):
    start = stats.get('start_time')
    end = stats.get('end_time')
    if start is None or end is None:
        return 0
    try:
        return max(float(end) - float(start), 0)
    except (TypeError, ValueError):
        return 0


def _safe_csv_value(value):
    """Prevent spreadsheet formula injection in exported CSV cells."""
    if isinstance(value, str) and value:
        stripped = value.lstrip()
        if stripped and stripped[0] in ('=', '+', '-', '@'):
            return "'" + value
    return value


def export_to_json(data, stats, output_file):
    """Export scan results to JSON format."""
    try:
        export_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': _duration_seconds(stats),
                'statistics': stats
            },
            'results': data
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return output_file
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_error
        log_error(f"IO error exporting to JSON: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error exporting to JSON: {e}", exc_info=True)
        return None

def export_to_csv(data, output_file, data_type='files'):
    """Export scan results to CSV format."""
    try:
        if not data:
            return None
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if data_type == 'files':
                fieldnames = ['ip', 'share', 'path', 'size', 'file_type', 'create_time', 'last_write_time']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            else:  # sensitive
                fieldnames = ['ip', 'share', 'path', 'category', 'match', 'file_type', 'downloaded_file']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            
            writer.writeheader()
            for row in data:
                writer.writerow({key: _safe_csv_value(value) for key, value in row.items()})
        
        return output_file
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_error
        log_error(f"IO error exporting to CSV: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error exporting to CSV: {e}", exc_info=True)
        return None

def export_statistics(stats, output_file):
    """Export statistics to a separate JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        return output_file
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_error
        log_error(f"IO error exporting statistics: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error exporting statistics: {e}", exc_info=True)
        return None

def get_export_filenames(base_name, format_type):
    """Generate export filenames with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format_type == 'json':
        return {
            'files': f"{base_name}_files_{timestamp}.json",
            'sensitive': f"{base_name}_sensitive_{timestamp}.json",
            'stats': f"{base_name}_stats_{timestamp}.json"
        }
    elif format_type == 'csv':
        return {
            'files': f"{base_name}_files_{timestamp}.csv",
            'sensitive': f"{base_name}_sensitive_{timestamp}.csv",
            'stats': f"{base_name}_stats_{timestamp}.json"  # Stats always JSON
        }
    else:
        return None
