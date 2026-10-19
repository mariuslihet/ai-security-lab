"""
Pytest configuration and environment fixtures for AI Security Lab.
Ensures repository root is included in sys.path for test runner discovery.
"""

import sys
from pathlib import Path

# Add root directory to sys.path
ROOT_DIR = Path(__file__).parent.resolve()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
