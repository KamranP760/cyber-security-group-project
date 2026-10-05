"""
NovaBank Security Dashboard - API

A tiny Flask server (port 5001) that reads the monitoring files and
returns JSON for the dashboard page. It never changes any data.

Run with:
  python dashboard/dashboard_api.py
(run from inside the security_monitoring_tool/ folder)
"""

import csv
import json
import os
import sys

from flask import Flask, jsonify, request, send_from_directory

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

app = Flask(__name__)
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))


@app.after_request
def allow_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def read_live():
    if not os.path.exists(config.LIVE_SNAPSHOT_PATH):
        return {"updated": None, "sessions": []}
    try:
        with open(config.LIVE_SNAPSHOT_PATH) as f:
            return json.load(f)
    except (ValueError, OSError):
        return {"updated": None, "sessions": []}


def clean_incident(row):
    return {
        "timestamp": row.get("timestamp", ""),
        "session": (row.get("session_key") or "")[:12],
        "user_id": row.get("user_id", ""),
        "risk_score": int(float(row.get("risk_score") or 0)),
        "risk_level": row.get("risk_level", ""),
        "action": row.get("action", ""),
        "reasons": [r for r in (row.get("reasons") or "").split("; ") if r],
        "outcome": row.get("outcome", ""),
    }


@app.get("/")
def home():
    page = os.path.join(DASHBOARD_DIR, "dashboard.html")
    if os.path.exists(page):
        return send_from_directory(DASHBOARD_DIR, "dashboard.html")
    return "NovaBank Dashboard API is running. dashboard.html is not created yet."


@app.get("/api/incidents")
def incidents():
    limit = max(1, min(request.args.get("limit", default=20, type=int), 200))
    rows = read_csv(config.INCIDENT_LOG_PATH)
    rows = [clean_incident(r) for r in rows][::-1][:limit]
    return jsonify({"incidents": rows})


@app.get("/api/sessions")
def sessions():
    limit = max(1, min(request.args.get("limit", default=20, type=int), 200))
    rows = read_csv(config.DATASET_PATH)
    rows = [r for r in rows if not str(r.get("session_key", "")).startswith("ip:")]
    rows = rows[::-1][:limit]
    for r in rows:
        r["session_key"] = r["session_key"][:12]
    return jsonify({"sessions": rows})


@app.get("/api/live")
def live():
    return jsonify(read_live())


@app.get("/api/summary")
def summary():
    dataset = read_csv(config.DATASET_PATH)
    real_keys = {r["session_key"] for r in dataset
                 if not str(r.get("session_key", "")).startswith("ip:")}

    incident_rows = [clean_incident(r) for r in read_csv(config.INCIDENT_LOG_PATH)]
    flagged = [i for i in incident_rows if i["risk_level"] == "MEDIUM"]
    high = [i for i in incident_rows if i["risk_level"] == "HIGH"]
    terminated = [i for i in high if i["outcome"].startswith("Session invalidated")]

    live_data = read_live()
    live_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for s in live_data.get("sessions", []):
        level = s.get("risk_level")
        if level in live_counts:
            live_counts[level] += 1

    return jsonify({
        "sessions_seen": len(real_keys),
        "total_incidents": len(incident_rows),
        "flagged_medium": len(flagged),
        "high_risk": len(high),
        "sessions_terminated": len(terminated),
        "live_sessions": len(live_data.get("sessions", [])),
        "live_by_level": live_counts,
        "live_updated": live_data.get("updated"),
    })


if __name__ == "__main__":
    print("=" * 50)
    print(" NovaBank Dashboard API")
    print(f" Open: http://127.0.0.1:{config.DASHBOARD_PORT}")
    print("=" * 50)
    app.run(host="127.0.0.1", port=config.DASHBOARD_PORT, debug=False)