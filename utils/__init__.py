"""
Utils package - exports from utils.py module.

The DateRange, html_to_text, and RecordDownloader classes/functions
are defined in utils.py at the project root level.
"""

import importlib.util
import os
import sys

# Load utils.py directly from the file path (bypasses package/module conflict)
_utils_py_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'utils.py')

spec = importlib.util.spec_from_file_location("_root_utils", _utils_py_path)
_root_utils = importlib.util.module_from_spec(spec)
sys.modules['_root_utils'] = _root_utils
spec.loader.exec_module(_root_utils)

# Re-export key classes and functions
DateRange = _root_utils.DateRange
html_to_text = _root_utils.html_to_text
RecordDownloader = _root_utils.RecordDownloader

__all__ = ['DateRange', 'html_to_text', 'RecordDownloader']
