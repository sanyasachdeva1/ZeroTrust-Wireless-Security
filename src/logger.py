import json
import os
from datetime import UTC, datetime
from pathlib import Path


DEFAULT_LOG_DIR = Path("logs")


def _log_dir():
    return Path(os.environ.get("ZT_LOG_DIR", DEFAULT_LOG_DIR))


def _soc_log_file():
    return _log_dir() / "alerts.log"


def _json_alert_file():
    return _log_dir() / "alerts.jsonl"


def _timestamp():
    return datetime.now(UTC).isoformat()


def log_alert(
    threat,
    mac=None,
    severity="HIGH",
    mitre_technique=None,
    action="Logged",
    risk_score=None,
    confidence=None,
    details=None,
):
    """
    Write both SOC-style text logs and structured JSON alerts.
    """

    log_dir = _log_dir()
    log_dir.mkdir(exist_ok=True)

    alert = {
        "timestamp": _timestamp(),
        "severity": severity,
        "threat": threat,
        "mac": mac,
        "mitre_technique": mitre_technique or "N/A",
        "action": action,
        "risk_score": risk_score,
        "confidence": confidence,
        "details": details or {}
    }
    risk_text = risk_score if risk_score is not None else "N/A"

    soc_log_entry = (
        f"{alert['timestamp']} | "
        f"Severity={alert['severity']} | "
        f"Threat={alert['threat']} | "
        f"MAC={alert['mac']} | "
        f"Risk={risk_text} | "
        f"MITRE={alert['mitre_technique']} | "
        f"Action={alert['action']}\n"
    )

    with open(_soc_log_file(), "a") as log_file:
        log_file.write(soc_log_entry)

    with open(_json_alert_file(), "a") as json_file:
        json_file.write(json.dumps(alert) + "\n")

    print(f"[ALERT] {soc_log_entry.strip()}")
