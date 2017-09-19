import os

"""
Python 2.7 behaves badly if there is no locale set. This adds a fallback to `en_US.UTF-8`.
"""

if not any(k in os.environ for k in ['LC_CTYPE', 'LC_ALL', 'LANG']):
    print("Warning: No locale set. Falling back to 'en_US.UTF-8'.")
    os.environ['LANG'] = 'en_US.UTF-8'
