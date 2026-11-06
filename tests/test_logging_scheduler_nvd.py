import logging
from datetime import datetime

from vulnr_scannr import nvd, scheduler
from vulnr_scannr.logging_setup import redact, setup_logging


def test_redaction():
    assert "[REDACTED]" in redact("net rpc -U CORP/bob%Hunter2 x")
    assert "Hunter2" not in redact("password=Hunter2")
    assert "Hunter2" not in redact("SMBPass Hunter2")
    assert "[REDACTED-HASH]" in redact("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
    assert redact("50% done") == "50% done"


def test_logger_writes_redacted_to_db(db):
    log = setup_logging(db, quiet=True)
    log.info("creds password=%s", "TopSecret")
    msgs = [r["message"] for r in db.rows("logs")]
    assert msgs and "TopSecret" not in msgs[-1]
    logging.getLogger("vulnr_scannr").handlers.clear()


def test_next_run_daily_and_weekly():
    now = datetime(2026, 11, 6, 4, 0)  # Friday
    assert scheduler.next_run(now, 3, 0, "daily") == datetime(2026, 11, 7, 3, 0)
    assert scheduler.next_run(now, 5, 0, "daily") == datetime(2026, 11, 6, 5, 0)
    assert scheduler.next_run(now, 3, 0, "weekly") == datetime(2026, 11, 9, 3, 0)  # Monday


def test_run_forever_with_fake_clock():
    t = [datetime(2026, 11, 6, 2, 59)]
    ran = []

    def sleep(s):
        t[0] = t[0].replace(hour=3, minute=0)

    def job():
        ran.append(1)
        raise RuntimeError("job errors must not kill the scheduler")

    assert scheduler.run_forever(job, 3, 0, "daily", sleep=sleep, clock=lambda: t[0], max_runs=1) == 1
    assert ran == [1]


def test_nvd_extract():
    payload = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]}}}]}
    assert nvd.extract_base_score(payload) == 10.0
    assert nvd.extract_base_score({}) is None
    assert nvd.lookup_cvss("not-a-cve") is None
