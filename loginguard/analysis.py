"""CSV validation, normalization, and transparent authentication detections."""
from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO, StringIO
from typing import BinaryIO

import pandas as pd

REQUIRED_COLUMNS = {"timestamp", "ip", "username", "status"}
ALIASES = {
    "timestamp": {"timestamp", "time", "datetime", "date", "horario", "data_hora", "datahora"},
    "ip": {"ip", "source_ip", "src_ip", "ip_address", "endereco_ip"},
    "username": {"username", "user", "account", "usuario", "usuário"},
    "status": {"status", "result", "outcome", "resultado"},
}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


class LogValidationError(ValueError):
    """Raised when a supplied CSV cannot safely be analyzed."""


@dataclass(frozen=True)
class DetectionConfig:
    window_minutes: int = 5
    failures_threshold: int = 5
    unique_users_threshold: int = 5
    success_after_failures: int = 3
    spray_window_minutes: int = 10

    def __post_init__(self):
        for name, value in vars(self).items():
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} deve ser um número inteiro maior que zero.")
        if self.window_minutes > 1440 or self.spray_window_minutes > 1440:
            raise ValueError("As janelas não podem exceder 1440 minutos.")


def _read_csv(source: str | bytes | BinaryIO, max_bytes: int) -> pd.DataFrame:
    if isinstance(source, str):
        payload = source.encode("utf-8-sig")
    elif isinstance(source, bytes):
        payload = source
    else:
        payload = source.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise LogValidationError(f"Arquivo excede o limite de {max_bytes // (1024 * 1024)} MB.")
    if not payload.strip():
        raise LogValidationError("O arquivo CSV está vazio.")
    try:
        return pd.read_csv(BytesIO(payload), dtype=str, keep_default_na=False)
    except Exception as exc:
        raise LogValidationError(f"Não foi possível ler o CSV: {exc}") from exc


def load_logs(source: str | bytes | BinaryIO, max_bytes: int = MAX_UPLOAD_BYTES) -> pd.DataFrame:
    """Read and validate a CSV. Required fields: timestamp, ip, username, status."""
    df = _read_csv(source, max_bytes)
    canonical = {}
    for col in df.columns:
        key = str(col).strip().lower().replace("-", "_").replace(" ", "_")
        for field, names in ALIASES.items():
            if key in names:
                canonical[col] = field
                break
    df = df.rename(columns=canonical)
    if df.columns.duplicated().any():
        df = df.loc[:, ~df.columns.duplicated()]
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise LogValidationError("Colunas obrigatórias ausentes: " + ", ".join(sorted(missing)))
    df = df[list(REQUIRED_COLUMNS)].copy()
    for col in REQUIRED_COLUMNS:
        df[col] = df[col].astype(str).str.strip()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if df["timestamp"].isna().any():
        raise LogValidationError(f"{int(df['timestamp'].isna().sum())} linha(s) têm horário inválido.")
    # Invalid addresses are rejected rather than silently grouped as a shared source.
    import ipaddress
    invalid_ip = []
    for idx, value in df["ip"].items():
        try:
            ipaddress.ip_address(value)
        except ValueError:
            invalid_ip.append(idx)
    if invalid_ip:
        raise LogValidationError(f"{len(invalid_ip)} linha(s) têm endereço IP inválido.")
    df["status"] = df["status"].str.lower().replace({
        "failed": "failure", "fail": "failure", "invalid": "failure", "denied": "failure",
        "malsucedido": "failure", "falha": "failure", "success": "success", "successful": "success",
        "succeeded": "success", "ok": "success", "sucesso": "success", "bem-sucedido": "success",
    })
    invalid_status = ~df["status"].isin(["failure", "success"])
    if invalid_status.any():
        vals = ", ".join(sorted(df.loc[invalid_status, "status"].unique())[:5])
        raise LogValidationError(f"Status não reconhecido: {vals}. Use success/failure ou equivalentes.")
    if (df["username"] == "").any():
        raise LogValidationError("Há linhas sem username.")
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def detect_alerts(logs: pd.DataFrame, config: DetectionConfig = DetectionConfig()) -> pd.DataFrame:
    """Return explainable, investigative alerts, never confirmed attack labels."""
    cols = ["timestamp", "ip", "severity", "alert_type", "attempts", "users", "justification"]
    if logs.empty:
        return pd.DataFrame(columns=cols)
    data = logs.sort_values("timestamp", kind="stable")
    alerts: list[dict] = []
    def add(ts, ip, severity, kind, attempts, users, reason):
        alerts.append({"timestamp": ts, "ip": ip, "severity": severity, "alert_type": kind,
                       "attempts": int(attempts), "users": ", ".join(sorted(set(users))), "justification": reason})

    # Sliding-window failure volume per IP.
    for ip, group in data[data.status == "failure"].groupby("ip", sort=False):
        times = group.timestamp.tolist()
        names = group.username.tolist()
        left = 0
        for right, ts in enumerate(times):
            while left <= right and (ts - times[left]).total_seconds() > config.window_minutes * 60:
                left += 1
            count = right - left + 1
            if count >= config.failures_threshold and (right == len(times)-1 or count != right-left):
                # Emit only at threshold crossing; avoid duplicate alerts for every row.
                if right == 0 or right-left+1 == config.failures_threshold:
                    add(ts, ip, "High", "Possible brute force", count, names[left:right+1],
                        f"{count} falhas deste IP em até {config.window_minutes} minutos (limiar: {config.failures_threshold}).")
        # Spraying: distinct accounts targeted by failures in configured window.
        left = 0
        for right, ts in enumerate(times):
            while left <= right and (ts-times[left]).total_seconds() > config.spray_window_minutes*60:
                left += 1
            segment_users = names[left:right+1]
            unique = set(segment_users)
            if len(unique) >= config.unique_users_threshold and len(set(names[left:right])) < config.unique_users_threshold:
                add(ts, ip, "High", "Possible password spraying", right-left+1, unique,
                    f"Falhas contra {len(unique)} contas distintas em até {config.spray_window_minutes} minutos (limiar: {config.unique_users_threshold}).")

    # A success is notable when preceded by several failures from same IP within window.
    for ip, group in data.groupby("ip", sort=False):
        events = group.to_dict("records")
        for idx, event in enumerate(events):
            if event["status"] != "success":
                continue
            start = event["timestamp"] - pd.Timedelta(minutes=config.window_minutes)
            preceding = [e for e in events[:idx] if e["status"] == "failure" and start <= e["timestamp"] < event["timestamp"]]
            if len(preceding) >= config.success_after_failures:
                add(event["timestamp"], ip, "Medium", "Success after repeated failures", len(preceding),
                    [e["username"] for e in preceding] + [event["username"]],
                    f"Login bem-sucedido após {len(preceding)} falhas do mesmo IP em {config.window_minutes} minutos; requer investigação.")

    result = pd.DataFrame(alerts, columns=cols)
    if not result.empty:
        result = result.drop_duplicates(subset=["timestamp", "ip", "alert_type"]).sort_values("timestamp", ascending=False).reset_index(drop=True)
    return result


def incident_report(alerts: pd.DataFrame) -> pd.DataFrame:
    """Select report columns without altering detection results."""
    return alerts[["timestamp", "ip", "severity", "alert_type", "attempts", "users", "justification"]].copy()
