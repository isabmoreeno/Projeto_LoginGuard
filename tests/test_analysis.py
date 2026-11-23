from io import BytesIO

import pandas as pd
import pytest

from loginguard.analysis import DetectionConfig, LogValidationError, detect_alerts, load_logs


def test_load_logs_normalizes_fields_and_status():
    logs = load_logs(b"timestamp,ip,username,status\n2026-01-01T00:00:00Z,192.0.2.1,alice,failed\n")
    assert len(logs) == 1
    assert logs.iloc[0].status == "failure"
    assert str(logs.timestamp.dt.tz) == "UTC"


def test_load_logs_rejects_missing_columns_and_bad_ip():
    with pytest.raises(LogValidationError, match="ausentes"):
        load_logs(b"ip,user\n192.0.2.1,a\n")
    with pytest.raises(LogValidationError, match="IP inv"):
        load_logs(b"timestamp,ip,username,status\n2026-01-01,not-ip,a,failure\n")


def test_load_logs_rejects_oversized_file():
    with pytest.raises(LogValidationError, match="excede"):
        load_logs(BytesIO(b"x" * 20), max_bytes=10)


def test_detects_brute_force_spraying_and_success_after_failures():
    rows=[]
    for minute,user in enumerate(["a","b","c","d","e"]):
        rows.append((f"2026-01-01T00:0{minute}:00Z","198.51.100.8",user,"failure"))
    rows.append(("2026-01-01T00:05:00Z","198.51.100.8","e","success"))
    csv="timestamp,ip,username,status\n"+"\n".join(",".join(row) for row in rows)
    alerts=detect_alerts(load_logs(csv))
    kinds=set(alerts.alert_type)
    assert "Possible brute force" in kinds
    assert "Possible password spraying" in kinds
    assert "Success after repeated failures" in kinds
    assert set(alerts.severity) <= {"High","Medium","Low"}


def test_config_validation():
    with pytest.raises(ValueError):
        DetectionConfig(failures_threshold=0)


def test_empty_frame_returns_reportable_columns():
    empty=detect_alerts(load_logs(b"timestamp,ip,username,status\n2026-01-01T00:00:00Z,192.0.2.1,a,success\n").iloc[0:0])
    assert list(empty.columns) == ["timestamp","ip","severity","alert_type","attempts","users","justification"]
