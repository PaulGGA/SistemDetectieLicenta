import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

REPORTS_TEMP_DIR = os.path.join(PROJECT_ROOT, "reports_temp")
os.makedirs(REPORTS_TEMP_DIR, exist_ok=True)

ipServer = "http://3.77.38.177:5000"