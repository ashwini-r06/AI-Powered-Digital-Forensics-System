
"""CyberSentry AI — Application Configuration."""

from pathlib import Path

APP_NAME = "CyberSentry AI"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "AI-Assisted Digital Forensics & Incident Response"

# Project directories
PROJECT_ROOT = Path(__file__).resolve().parent

DATA_DIR = PROJECT_ROOT / "data"
SAMPLE_LOGS_DIR = DATA_DIR / "sample_logs"
DATASETS_DIR = DATA_DIR / "datasets"

ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Upload limits
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_UPLOAD_ROWS = 100_000
MAX_FILES_PER_UPLOAD = 10

# Supported evidence file formats
ALLOWED_UPLOAD_EXTENSIONS = {".csv", ".json"}

# Anomaly detection settings
ANOMALY_CONTAMINATION = 0.1
ANOMALY_RANDOM_STATE = 42
MINIMUM_ANOMALY_EVENTS = 5

# Default investigation settings
DEFAULT_CASE_PRIORITY = "MEDIUM"
DEFAULT_INCIDENT_SEVERITY = "MEDIUM"

# Create required directories if they do not exist
for directory in (
    DATA_DIR,
    SAMPLE_LOGS_DIR,
    DATASETS_DIR,
    ARTIFACTS_DIR,
    REPORTS_DIR,
):
    directory.mkdir(parents=True, exist_ok=True)
