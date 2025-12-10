#!/usr/bin/env python3
"""
JESUR - Enhanced SMB Share Scanner
Main entry point

Developer: Cuma KURT
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import sys
import os

# Ensure the current directory is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jesur.main import main

if __name__ == "__main__":
    main()
