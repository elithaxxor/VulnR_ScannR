"""Minimal daily/weekly scheduler (stdlib replacement for the ``schedule`` dependency)."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta

log = logging.getLogger("vulnr_scannr")


def next_run(now: datetime, hour: int, minute: int, frequency: str, weekday: int = 0) -> datetime:
    """Next occurrence after ``now``. ``weekday`` 0=Monday (legacy default)."""
    if frequency not in ("daily", "weekly"):
        raise ValueError("frequency must be 'daily' or 'weekly'")
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "daily":
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    days_ahead = (weekday - now.weekday()) % 7
    candidate += timedelta(days=days_ahead)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate


def run_forever(
    job: Callable[[], None],
    hour: int,
    minute: int,
    frequency: str,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], datetime] = datetime.now,
    max_runs: int | None = None,
) -> int:
    runs = 0
    try:
        while max_runs is None or runs < max_runs:
            target = next_run(clock(), hour, minute, frequency)
            log.info("[scheduler] next run at %s", target.strftime("%Y-%m-%d %H:%M"))
            while (remaining := (target - clock()).total_seconds()) > 0:
                sleep(min(remaining, 60))
            try:
                job()
            except Exception:  # noqa: BLE001 - keep the scheduler alive
                log.exception("[scheduler] scheduled job failed")
            runs += 1
    except KeyboardInterrupt:
        log.info("[scheduler] stopped by user")
    return runs
