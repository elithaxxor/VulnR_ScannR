"""Export database tables to CSV/JSON/XML and render reports (stdlib only)."""

from __future__ import annotations

import csv
import html
import json
import logging
import xml.etree.ElementTree as ET  # noqa: S405 - used only to *build* XML
from pathlib import Path
from typing import Any

from vulnr_scannr.db import EXPORT_TABLES, Database, now

log = logging.getLogger("vulnr_scannr")

FORMATS = ("csv", "json", "xml")


def _safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in CSV cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def export_tables(
    db: Database,
    out_dir: str | Path = "exports",
    formats: tuple[str, ...] = FORMATS,
    tables: tuple[str, ...] = EXPORT_TABLES,
) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for table in tables:
        rows = db.rows(table)
        if "csv" in formats:
            p = out / f"{table}.csv"
            with p.open("w", newline="", encoding="utf-8") as fh:
                cols = list(rows[0].keys()) if rows else []
                w = csv.writer(fh)
                w.writerow(cols)
                for r in rows:
                    w.writerow([_safe_cell(r[c]) for c in cols])
            written.append(p)
        if "json" in formats:
            p = out / f"{table}.json"
            p.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
            written.append(p)
        if "xml" in formats:
            root = ET.Element(table)
            for r in rows:
                rec = ET.SubElement(root, "record")
                for k, v in r.items():
                    ET.SubElement(rec, k).text = "" if v is None else str(v)
            ET.indent(root)
            p = out / f"{table}.xml"
            ET.ElementTree(root).write(p, encoding="utf-8", xml_declaration=True)
            written.append(p)
    log.info("Exported %d file(s) to %s", len(written), out)
    return written


def render_html_report(db: Database, path: str | Path = "reports/report.html") -> Path:
    """Write a self-contained static HTML report (all values HTML-escaped)."""
    scores = db.latest_scores()
    recs = db.rows("remediation_recommendations")
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(str(s['host']))}</td><td>{s['final_score']}</td><td class='{e(s['risk_category'])}'>"
        f"{e(s['risk_category'])}</td><td>{s['open_ports']}</td><td>{s['vulnerabilities']}</td>"
        f"<td>{s.get('cvss_score') or 0}</td></tr>"
        for s in scores
    )
    rec_rows = "".join(
        f"<tr><td>{e(r['host'])}</td><td>{e(r['severity'])}</td><td>{e(r['finding'])}</td>"
        f"<td>{e(r['remediation'])}</td><td><a href='{e(r['reference'])}'>{e(r['reference'])}</a></td></tr>"
        for r in recs
    )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>VulnR_ScannR report</title><style>
body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse;margin-bottom:2em}}
td,th{{border:1px solid #ccc;padding:4px 8px}}.Critical{{background:#f88}}.High{{background:#fb8}}
.Medium{{background:#ff8}}.Low{{background:#8f8}}</style></head><body>
<h1>VulnR_ScannR report</h1><p>Generated {e(now())}.
For authorized assessments only.</p>
<h2>Host scores (latest per host)</h2><table><tr><th>Host</th><th>Score</th><th>Risk</th>
<th>Open ports</th><th>Findings</th><th>CVSS sum</th></tr>{rows}</table>
<h2>Remediation recommendations</h2><table><tr><th>Host</th><th>Severity</th><th>Finding</th>
<th>Remediation</th><th>Reference</th></tr>{rec_rows}</table></body></html>
"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(doc, encoding="utf-8")
    log.info("HTML report written to %s", p)
    return p


def plot_scores(db: Database, path: str | Path = "reports/vulnerability_scores.png") -> Path | None:
    """Bar chart of latest scores. Requires the optional ``plot`` extra (matplotlib)."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning("matplotlib not installed; install with: pip install 'vulnr-scannr[plot]'")
        return None
    scores = db.latest_scores()
    if not scores:
        log.warning("No scores in database; nothing to plot.")
        return None
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(max(6, len(scores) * 0.6), 4))
    ax.bar([s["host"] for s in scores], [s["final_score"] for s in scores])
    ax.set_ylim(0, 100)
    ax.set_ylabel("Score (higher is better)")
    ax.set_title("Vulnerability scores")
    ax.tick_params(axis="x", rotation=45)
    fig.tight_layout()
    fig.savefig(p)
    plt.close(fig)
    log.info("Chart written to %s", p)
    return p
