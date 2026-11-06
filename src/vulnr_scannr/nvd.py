"""Optional CVSS lookup via the NVD CVE API 2.0 (opt-in, stdlib only).

The legacy code used the NVD 1.0 endpoint, which NVD has retired.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from functools import lru_cache

log = logging.getLogger("vulnr_scannr")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def extract_base_score(payload: dict) -> float | None:
    for vuln in payload.get("vulnerabilities", []):
        metrics = vuln.get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                score = m.get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)
    return None


@lru_cache(maxsize=512)
def lookup_cvss(cve: str, timeout: float = 10.0) -> float | None:
    if not _CVE_RE.match(cve):
        return None
    req = urllib.request.Request(NVD_URL.format(cve=cve), headers={"User-Agent": "vulnr-scannr"})  # noqa: S310  # nosec B310
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            return extract_base_score(json.load(resp))
    except Exception as exc:  # noqa: BLE001
        log.warning("NVD lookup failed for %s: %s", cve, exc)
        return None
