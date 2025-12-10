"""
JESUR - Enhanced SMB Share Scanner
File analysis and sensitive content detection module

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import os
import json
import re
import magic
import io
import docx
# import pdfplumber # Imported on demand to optional dependencies don't crash everything if missing
import openpyxl
from jesur.utils.cache import cache_manager

# Load patterns from JSON
PATTERNS_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'patterns.json')
PATTERNS = {}
try:
    with open(PATTERNS_FILE, 'r') as f:
        PATTERNS = json.load(f)
except FileNotFoundError:
    from jesur.utils.logger import log_warning
    log_warning(f"Patterns file not found: {PATTERNS_FILE}")
    PATTERNS = {"patterns": {}, "false_positives": [], "security_keywords": ""}
except json.JSONDecodeError as e:
    from jesur.utils.logger import log_error
    log_error(f"Invalid JSON in patterns file: {e}")
    PATTERNS = {"patterns": {}, "false_positives": [], "security_keywords": ""}
except Exception as e:
    from jesur.utils.logger import log_error
    log_error(f"Could not load patterns.json: {e}", exc_info=True)
    PATTERNS = {"patterns": {}, "false_positives": [], "security_keywords": ""}

# Global magic instance for better performance
_magic_instance = None

def _get_magic_instance():
    """Get or create global magic instance."""
    global _magic_instance
    if _magic_instance is None:
        _magic_instance = magic.Magic(mime=True)
    return _magic_instance

def get_file_type(file_content: bytes) -> str:
    """
    Detect file type using magic library.
    
    Args:
        file_content: File content as bytes
        
    Returns:
        MIME type string or "unknown" if detection fails
    """
    try:
        mime = _get_magic_instance()
        file_type = mime.from_buffer(file_content)
        
        # Excel and Word checks
        if file_type == 'application/vnd.ms-excel' or \
           file_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' or \
           file_type.startswith('application/vnd.ms-excel.') or \
           '.xls' in file_type.lower():
            return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            
        if file_type == 'application/msword' or \
           file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' or \
           file_type.startswith('application/vnd.ms-word.') or \
           '.doc' in file_type.lower():
            return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            
        return file_type
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"File type detection IO error: {e}")
        return "unknown"
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"File type detection failed: {e}")
        return "unknown"

def extract_pdf_content(file_content: bytes) -> str:
    """
    Extract text content from PDF file.
    
    Args:
        file_content: PDF file content as bytes
        
    Returns:
        Extracted text content or None if extraction fails
    """
    try:
        import pdfplumber
        with io.BytesIO(file_content) as pdf_file:
            with pdfplumber.open(pdf_file) as pdf:
                text = ""
                for page in pdf.pages:
                    text += page.extract_text() or ""
        return text
    except ImportError:
        from jesur.utils.logger import log_debug
        log_debug("pdfplumber not available, PDF extraction skipped")
        return None
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"PDF extraction IO error: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"PDF extraction failed: {e}")
        return None

def extract_docx_content(file_content: bytes) -> str:
    """
    Extract text content from DOCX file.
    
    Args:
        file_content: DOCX file content as bytes
        
    Returns:
        Extracted text content or None if extraction fails
    """
    try:
        doc = docx.Document(io.BytesIO(file_content))
        return " ".join([paragraph.text for paragraph in doc.paragraphs])
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"DOCX extraction IO error: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"DOCX extraction failed: {e}")
        return None

def extract_xlsx_content(file_content: bytes) -> str:
    """
    Extract text content from XLSX file.
    
    Args:
        file_content: XLSX file content as bytes
        
    Returns:
        Extracted text content or None if extraction fails
    """
    try:
        wb = openpyxl.load_workbook(io.BytesIO(file_content), data_only=True)
        text = []
        for sheet in wb.sheetnames:
            ws = wb[sheet]
            for row in ws.iter_rows():
                text.extend(str(cell.value) for cell in row if cell.value is not None)
        return " ".join(text)
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"XLSX extraction IO error: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"XLSX extraction failed: {e}")
        return None

def check_sensitive_patterns(file_content: bytes, file_type: str, ip: str) -> list:
    """
    Check file content for sensitive patterns defined in patterns.json.
    
    Args:
        file_content: File content as bytes
        file_type: MIME type of the file
        ip: IP address of the host (for logging)
        
    Returns:
        List of detected sensitive pattern matches
    """
    results_list = []
    content = None

    # Extract text based on file type
    if file_type.startswith('application/pdf'):
        content = extract_pdf_content(file_content)
    elif file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        content = extract_docx_content(file_content)
    elif file_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
        content = extract_xlsx_content(file_content)
    elif file_type.startswith('text/'):
        try:
            content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = file_content.decode('latin-1')
            except UnicodeDecodeError:
                from jesur.utils.logger import log_debug
                log_debug("Failed to decode text file content")
                return results_list

    if not content:
        return results_list

    # Check security keywords
    sec_keywords = PATTERNS.get('security_keywords', '')
    if sec_keywords:
        security_pattern = cache_manager.get_compiled_pattern(sec_keywords)
        if security_pattern.search(content):
            results_list.append({
                'category': 'security_keyword',
                'match': 'Contains security-related keywords'
            })

    # Prepare patterns
    sensitive_patterns = PATTERNS.get('patterns', {})
    false_positives = PATTERNS.get('false_positives', [])
    compiled_fps = [cache_manager.get_compiled_pattern(fp) for fp in false_positives]

    # Limit matches per category to prevent output flooding
    from jesur.core.constants import MAX_MATCHES_PER_CATEGORY
    category_counts = {}

    lines = content.split('\n')
    for category, pattern in sensitive_patterns.items():
        # Compile pattern
        compiled_pattern = cache_manager.get_compiled_pattern(pattern)
        category_counts[category] = 0
        
        for i, line in enumerate(lines):
            # Stop if we've found enough matches in this category
            if category_counts[category] >= MAX_MATCHES_PER_CATEGORY:
                break
                
            for match in compiled_pattern.finditer(line):
                if category_counts[category] >= MAX_MATCHES_PER_CATEGORY:
                    break
                    
                match_str = match.group(0)
                # False positive check
                if not any(fp.search(match_str) for fp in compiled_fps):
                    # (Simplified context check logic here for performance)
                    results_list.append({
                        'category': category,
                        'match': match_str
                    })
                    category_counts[category] += 1

    return results_list
