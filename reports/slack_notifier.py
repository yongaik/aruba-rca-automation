# reports/slack_notifier.py
import os
import json
import logging
import requests

logger = logging.getLogger(__name__)

SEV_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "✅"
}
SEV_COLOUR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM": "#d97706", "LOW": "#16a34a", "NONE": "#2563eb"
}


def post_to_slack(rca: dict, md_path: str, html_path: str) -> bool:
    """Post RCA summary card to Slack via Incoming Webhook."""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        logger.warning("SLACK_WEBHOOK_URL not set — skipping Slack notification.")
        return False

    sev = rca.get("overall_severity", "UNKNOWN")
    rc = rca.get("root_cause", {})
    scope = rca.get("affected_scope", {})
    steps = rca.get("recommended_steps", [])

    # Build top 3 steps snippet
    top_steps = ""
    for s in steps[:3]:
        top_steps += f"\n*{s['priority']}.* {s['action']} `{s.get('system','')}` _{s.get('estimated_time','')}_"

    payload = {
        "attachments": [
            {
                "color": SEV_COLOUR.get(sev, "#6b7280"),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{SEV_EMOJI.get(sev, '⚪')} Aruba Network RCA — {sev}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Issue Detected:* {'Yes' if rca.get('issue_detected') else 'No'}\n"
                                    f"*Domain:* {rc.get('domain','N/A')}  |  "
                                    f"*Confidence:* {rc.get('confidence','N/A')}\n"
                                    f"*Users Impacted:* {scope.get('estimated_users_impacted','Unknown')}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Summary:*\n{rca.get('executive_summary','N/A')}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Root Cause:*\n{rc.get('description','N/A')[:400]}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Top Remediation Steps:*{top_steps if top_steps else '_None_'}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"📄 *MD:* `{md_path}`  |  "
                                    f"🌐 *HTML:* `{html_path}`  |  "
                                    f"⏰ {rca.get('rca_timestamp','')}"
                                ),
                            }
                        ],
                    },
                ],
            }
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Slack: RCA notification posted successfully.")
        return True
    except requests.RequestException as e:
        logger.error(f"Slack post failed: {e}")
        return False
