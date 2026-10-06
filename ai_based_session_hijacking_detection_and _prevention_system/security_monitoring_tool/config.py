"""
Monitoring Agent - Configuration

Everything the agent needs to know: where the bank API lives, how often
to poll it, and the simple thresholds used to derive features.
"""

import os

BANK_API_URL = os.environ.get("BANK_API_URL", "http://127.0.0.1:5000")

POLL_INTERVAL_SECONDS = 2

SESSION_IDLE_SECONDS = 15

RAW_LOG_PATH = os.path.join(os.path.dirname(__file__), "dataset", "raw_logs.csv")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "session_dataset.csv")

UNUSUAL_ENDPOINT_THRESHOLD = 2

UNUSUAL_TRANSACTION_THRESHOLD = 2

# How far back (seconds) to look for failed logins by the same user
# when a new session starts, so they get counted into that session.
FAILED_LOGIN_LOOKBACK_SECONDS = 300

# ---- Prevention settings ----
INCIDENT_LOG_PATH = os.path.join(os.path.dirname(__file__), "dataset", "incidents.csv")

# If True, HIGH-risk sessions are terminated via the bank API.
# Set to False to only log incidents (safe "observe only" mode).
INVALIDATE_ON_HIGH = True

# ---- Dashboard settings ----
LIVE_SNAPSHOT_PATH = os.path.join(os.path.dirname(__file__), "dataset", "live_sessions.json")
DASHBOARD_PORT = 5001