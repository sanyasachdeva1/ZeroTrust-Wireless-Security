import json
import shutil
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

sys.path.append(str(SRC_DIR))


@pytest.fixture(autouse=True)
def isolated_lab_files(tmp_path, monkeypatch):
    trust_config = tmp_path / "trusted_devices.json"
    detection_rules = tmp_path / "detection_rules.json"
    log_dir = tmp_path / "logs"

    shutil.copy(PROJECT_ROOT / "config" / "trusted_devices.json", trust_config)
    shutil.copy(PROJECT_ROOT / "config" / "detection_rules.json", detection_rules)

    config = json.loads(trust_config.read_text())
    config.setdefault("security_settings", {})["persist_trust_updates"] = True
    trust_config.write_text(json.dumps(config, indent=2) + "\n")

    monkeypatch.setenv("ZT_TRUST_CONFIG_FILE", str(trust_config))
    monkeypatch.setenv("ZT_DETECTION_RULES_FILE", str(detection_rules))
    monkeypatch.setenv("ZT_LOG_DIR", str(log_dir))

    from attack_detector import reset_detection_state

    reset_detection_state()
    yield
    reset_detection_state()
