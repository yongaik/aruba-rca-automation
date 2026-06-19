# main.py
"""
Unified entry point for the Aruba RCA Automation workflow.

Usage:
  python main.py run                      # On-demand single run
  python main.py schedule                 # Start cron scheduler
  python main.py webhook                  # Start webhook listener (HTTP)
  python main.py schedule --also-webhook  # Scheduler + webhook together
  python main.py slack-listen             # Listen to Slack for UXI alerts
"""
import os
import sys
import json
import logging
import argparse
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load .env before importing any module that reads env vars
load_dotenv()

from collectors.uxi_collector import UXICollector
from collectors.central_collector import CentralCollector
from collectors.clearpass_collector import ClearPassCollector
from analysis.rca_engine import RCAEngine
from reports.markdown_reporter import generate_markdown
from reports.html_reporter import generate_html
from reports.slack_notifier import post_to_slack

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("rca_workflow.log"),
    ],
)
logger = logging.getLogger("main")

LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", 30))
OUTPUT_DIR = os.getenv("REPORT_DIR", "./output")


def run_rca_workflow(trigger_context: str = "on_demand") -> dict:
    """
    Execute the full RCA workflow:
    1. Collect data from all three systems
    2. Run Claude RCA analysis
    3. Generate Markdown + HTML reports
    4. Post Slack notification
    5. Return the RCA result dict
    """
    logger.info(f"=== Starting RCA Workflow (trigger: {trigger_context}) ===")
    start = datetime.now(timezone.utc)

    # ── Data Collection ───────────────────────────────────────────────────
    try:
        uxi_data = UXICollector(LOOKBACK_MINUTES).collect_all()
        logger.info("✓ UXI data collected")
    except Exception as e:
        logger.error(f"✗ UXI collection failed: {e}")
        uxi_data = {"source": "uxi", "error": str(e)}

    try:
        central_data = CentralCollector(LOOKBACK_MINUTES).collect_all()
        logger.info("✓ Aruba Central data collected")
    except Exception as e:
        logger.error(f"✗ Central collection failed: {e}")
        central_data = {"source": "aruba_central", "error": str(e)}

    try:
        clearpass_data = ClearPassCollector(LOOKBACK_MINUTES).collect_all()
        logger.info("✓ ClearPass data collected")
    except Exception as e:
        logger.error(f"✗ ClearPass collection failed: {e}")
        clearpass_data = {"source": "clearpass", "error": str(e)}

    # ── RCA Analysis ──────────────────────────────────────────────────────
    engine = RCAEngine()
    rca_result = engine.analyse(
        uxi_data=uxi_data,
        central_data=central_data,
        clearpass_data=clearpass_data,
        trigger_context=trigger_context,
    )

    # ── Report Generation ─────────────────────────────────────────────────
    raw_snapshot = {
        "uxi": uxi_data,
        "central": central_data,
        "clearpass": clearpass_data,
    }
    md_path = generate_markdown(rca_result, raw_snapshot, OUTPUT_DIR)
    html_path = generate_html(rca_result, OUTPUT_DIR)
    logger.info(f"Reports saved:\n  MD:   {md_path}\n  HTML: {html_path}")

    # ── Slack Notification ────────────────────────────────────────────────
    # Only notify if an issue was detected (or severity is HIGH/CRITICAL)
    sev = rca_result.get("overall_severity", "NONE")
    if rca_result.get("issue_detected") or sev in ("HIGH", "CRITICAL"):
        post_to_slack(rca_result, md_path, html_path)
    else:
        logger.info("No issue detected — skipping Slack notification.")

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info(f"=== RCA Workflow complete in {elapsed:.1f}s ===")
    return rca_result


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Aruba Campus Network RCA Automation"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("run", help="Run a single on-demand RCA analysis")

    schedule_parser = sub.add_parser("schedule", help="Start scheduled polling")
    schedule_parser.add_argument(
        "--also-webhook", action="store_true",
        help="Also start the webhook listener alongside the scheduler"
    )

    sub.add_parser("webhook", help="Start the webhook listener server only")

    sub.add_parser(
        "slack-listen",
        help="Connect to Slack via Socket Mode and trigger RCA on UXI alert notifications"
    )

    args = parser.parse_args()

    if args.command == "run" or args.command is None:
        result = run_rca_workflow("on_demand")
        print(json.dumps(result, indent=2))

    elif args.command == "schedule":
        from triggers.scheduler import start_scheduler
        if getattr(args, "also_webhook", False):
            import threading
            from triggers.webhook_server import start_webhook_server
            t = threading.Thread(target=start_webhook_server, daemon=True)
            t.start()
        start_scheduler(run_rca_workflow)

    elif args.command == "webhook":
        from triggers.webhook_server import start_webhook_server
        start_webhook_server(run_rca_workflow)

    elif args.command == "slack-listen":
        from triggers.slack_listener import start_slack_listener
        start_slack_listener(run_rca_workflow)


if __name__ == "__main__":
    main()
