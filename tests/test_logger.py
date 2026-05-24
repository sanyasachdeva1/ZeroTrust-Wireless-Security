import json
import os
from pathlib import Path

import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from logger import log_alert


def test_json_alert_is_written():
    log_alert(
        threat="Test Alert",
        mac="AA:BB:CC:DD:EE:01",
        severity="LOW",
        action="Testing JSON alert output"
    )

    content = Path(os.environ["ZT_LOG_DIR"], "alerts.jsonl").read_text().strip()
    alert = json.loads(content)

    assert alert["threat"] == "Test Alert"
    assert alert["severity"] == "LOW"
    assert alert["mac"] == "AA:BB:CC:DD:EE:01"
