import json
from datetime import datetime, UTC
from pathlib import Path


LOG_DIR = Path("logs")
SOC_LOG_FILE = LOG_DIR / "alerts.log"
JSON_ALERT_FILE = LOG_DIR / "alerts.jsonl"


def _timestamp():
	return datetime.now(UTC).isoformat()

def log_alert(
    threat,
    mac=None,
    severity="HIGH",
    mitre_technique=None,
    action="Logged",
    details=None,
):
    """
    Write both SOC-style text logs and structured JSON alerts.
    """

    LOG_DIR.mkdir(exist_ok=True)

    alert = {
        "timestamp": _timestamp(),
        "severity": severity,
        "threat": threat,
        "mac": mac,
        "mitre_technique": mitre_technique or "N/A",
        "action": action,
        "details": details or {}
    }

    soc_log_entry = (
        f"{alert['timestamp']} | "
        f"Severity={alert['severity']} | "
        f"Threat={alert['threat']} | "
        f"MAC={alert['mac']} | "
        f"MITRE={alert['mitre_technique']} | "
        f"Action={alert['action']}\n"
    )

    with open(SOC_LOG_FILE, "a") as log_file:
        log_file.write(soc_log_entry)

    with open(JSON_ALERT_FILE, "a") as json_file:
        json_file.write(json.dumps(alert) + "\n")

    print(f"[ALERT] {soc_log_entry.strip()}")
