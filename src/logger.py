from datetime import datetime
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "alerts.log"


def log_alert(threat, mac, mitre_technique=None, action=None, severity="HIGH"):
    LOG_DIR.mkdir(exist_ok=True)

    timestamp = datetime.utcnow().isoformat() + "Z"

    log_entry = (
        f"{timestamp} | "
        f"Severity={severity} | "
        f"Threat={threat} | "
        f"MAC={mac} | "
        f"MITRE={mitre_technique or 'N/A'} | "
        f"Action={action or 'Logged'}\n"
    )

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)

    print(f"[ALERT] {log_entry.strip()}")
