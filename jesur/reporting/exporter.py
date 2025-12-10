"""
JESUR - Enhanced SMB Share Scanner
Export module - JSON and CSV export functionality

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import json
import csv
import os
from datetime import datetime

def export_to_json(data, stats, output_file):
    """Export scan results to JSON format."""
    try:
        export_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': stats.get('end_time', 0) - stats.get('start_time', 0) if stats.get('start_time') else 0,
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
                writer.writerow(row)
        
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
    
    # Create reports directory if it doesn't exist
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    
    if format_type == 'json':
        return {
            'files': os.path.join(reports_dir, f"{base_name}_files_{timestamp}.json"),
            'sensitive': os.path.join(reports_dir, f"{base_name}_sensitive_{timestamp}.json"),
            'stats': os.path.join(reports_dir, f"{base_name}_stats_{timestamp}.json")
        }
    elif format_type == 'csv':
        return {
            'files': os.path.join(reports_dir, f"{base_name}_files_{timestamp}.csv"),
            'sensitive': os.path.join(reports_dir, f"{base_name}_sensitive_{timestamp}.csv"),
            'stats': os.path.join(reports_dir, f"{base_name}_stats_{timestamp}.json")  # Stats always JSON
        }
    else:
        return None
