from datetime import datetime

def log_alert(threat, mac, mitre_technique=None, action=None):
    timestamp = datetime.utcnow().isoformat()

    log_entry = (
        f"{timestamp} | "
        f"Threat={threat} | "
        f"MAC={mac} | "
        f"MITRE={mitre_technique} | "
        f"Action={action}\n"
    )

    with open("logs/alerts.log", "a") as log_file:
        log_file.write(log_entry)

    print(f"[ALERT] {log_entry.strip()}")

