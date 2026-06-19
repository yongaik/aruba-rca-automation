# reports/html_reporter.py
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_html(rca: dict, output_dir: str = "./output") -> str:
    """Generate a self-contained HTML RCA report with status cards and tables."""

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_dir = Path(output_dir) / ts
    report_dir.mkdir(parents=True, exist_ok=True)
    filepath = report_dir / "rca_report.html"

    sev = rca.get("overall_severity", "NONE")
    sev_colour = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#d97706", "LOW": "#16a34a", "NONE": "#2563eb"
    }.get(sev, "#6b7280")

    rc = rca.get("root_cause", {})
    scope = rca.get("affected_scope", {})
    steps = rca.get("recommended_steps", [])

    steps_html = ""
    for s in steps:
        steps_html += f"""
        <div class="step">
          <div class="step-header">
            <span class="step-num">{s['priority']}</span>
            <strong>{s['action']}</strong>
            <span class="badge">{s.get('system','')}</span>
            <span class="time">⏱ {s.get('estimated_time','')}</span>
          </div>
          <p>{s.get('detail','').replace(chr(10),'<br>')}</p>
        </div>"""

    evidence_html = "".join(
        f"<li>{e}</li>" for e in rc.get("supporting_evidence", [])
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network RCA Report — {ts}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a;
         color: #e2e8f0; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; color: #f8fafc; }}
  h2 {{ font-size: 1.15rem; color: #94a3b8; margin: 2rem 0 1rem;
        text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #334155;
        padding-bottom: 0.5rem; }}
  .severity-badge {{ display: inline-block; padding: 0.35rem 1rem; border-radius: 999px;
                     font-weight: 700; font-size: 0.9rem; color: white;
                     background: {sev_colour}; margin-bottom: 1.5rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 1.25rem;
           border-left: 4px solid {sev_colour}; }}
  .card-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase;
                 letter-spacing: 0.05em; margin-bottom: 0.4rem; }}
  .card-value {{ font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }}
  .summary {{ background: #1e293b; border-radius: 12px; padding: 1.5rem;
              margin-bottom: 2rem; line-height: 1.7; color: #cbd5e1; }}
  .root-cause {{ background: #1e293b; border-radius: 12px; padding: 1.5rem;
                 margin-bottom: 2rem; }}
  .root-cause p {{ margin-top: 0.75rem; line-height: 1.7; color: #cbd5e1; }}
  .root-cause ul {{ margin-top: 0.75rem; padding-left: 1.5rem; color: #94a3b8;
                    line-height: 1.8; }}
  .step {{ background: #1e293b; border-radius: 10px; padding: 1.25rem;
           margin-bottom: 1rem; border: 1px solid #334155; }}
  .step-header {{ display: flex; align-items: center; gap: 0.75rem;
                  margin-bottom: 0.75rem; flex-wrap: wrap; }}
  .step-num {{ background: {sev_colour}; color: white; border-radius: 50%;
               width: 28px; height: 28px; display: flex; align-items: center;
               justify-content: center; font-weight: 700; font-size: 0.85rem;
               flex-shrink: 0; }}
  .step p {{ color: #94a3b8; line-height: 1.7; font-size: 0.9rem; }}
  .badge {{ background: #334155; color: #94a3b8; border-radius: 6px;
            padding: 0.2rem 0.6rem; font-size: 0.75rem; font-weight: 600; }}
  .time {{ color: #64748b; font-size: 0.8rem; margin-left: auto; }}
  .footer {{ text-align: center; color: #334155; font-size: 0.8rem; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>📡 Network RCA Report</h1>
  <p style="color:#64748b;margin-bottom:1rem;">{rca.get('rca_timestamp','')}</p>
  <div class="severity-badge">{sev}</div>

  <div class="cards">
    <div class="card">
      <div class="card-label">Issue Detected</div>
      <div class="card-value">{'Yes' if rca.get('issue_detected') else 'No'}</div>
    </div>
    <div class="card">
      <div class="card-label">Root Cause Domain</div>
      <div class="card-value" style="font-size:0.95rem">{rc.get('domain','N/A')}</div>
    </div>
    <div class="card">
      <div class="card-label">Confidence</div>
      <div class="card-value">{rc.get('confidence','N/A')}</div>
    </div>
    <div class="card">
      <div class="card-label">Users Impacted</div>
      <div class="card-value">{scope.get('estimated_users_impacted','?')}</div>
    </div>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary">{rca.get('executive_summary','N/A')}</div>

  <h2>Root Cause</h2>
  <div class="root-cause">
    <strong style="color:#f1f5f9">{rc.get('domain','N/A')}</strong>
    <p>{rc.get('description','N/A')}</p>
    <ul>{evidence_html}</ul>
  </div>

  <h2>Recommended Steps</h2>
  {steps_html}

  <div class="footer">Generated by Aruba RCA Automation · Claude claude-sonnet-4</div>
</div>
</body>
</html>"""

    filepath.write_text(html, encoding="utf-8")
    return str(filepath)
