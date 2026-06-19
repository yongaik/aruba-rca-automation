# analysis/rca_engine.py
"""
RCA Engine: sends collected network telemetry to Claude claude-sonnet-4
and returns a structured root cause analysis.
"""
import os
import json
import logging
from datetime import datetime, timezone

import anthropic

logger = logging.getLogger(__name__)

# ── RCA System Prompt ─────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are a senior HPE Aruba network engineer and AI root cause analysis (RCA) specialist.
You have deep expertise in:
- Aruba wireless infrastructure (APs, WLAN controllers, Aruba Central NMS)
- ClearPass Policy Manager (RADIUS, 802.1X EAP, MAC Authentication, policy enforcement)
- Aruba User Experience Insight (UXI) synthetic testing and application performance monitoring
- IEEE 802.11 wireless standards and RF troubleshooting
- Campus LAN design, PoE, switching, and network fundamentals

You receive structured JSON telemetry data collected from all three systems over a
recent lookback window. Your job is to:

1. Identify whether a user-impacting issue exists across any of these failure domains:
   - AUTHENTICATION (ClearPass RADIUS rejections, 802.1X/EAP failures, policy mismatches)
   - RF/WIRELESS (poor SNR, high interference, channel utilization, AP failures, roaming issues)
   - APPLICATION PERFORMANCE (latency, packet loss, throughput degradation via UXI tests)
   - DHCP/DNS (DHCP exhaustion, DNS resolution failures via UXI synthetic tests)

2. Perform cross-system correlation — for example:
   - ClearPass auth failures + UXI wireless test failures → likely RADIUS or EAP misconfiguration
   - High channel utilization in Central + high latency in UXI → RF congestion root cause
   - UXI DHCP failures + no ClearPass sessions → possible DHCP scope exhaustion

3. Identify the PRIMARY root cause with high confidence.

4. Identify any CONTRIBUTING factors (secondary issues that worsen the primary problem).

5. Assess SEVERITY: CRITICAL / HIGH / MEDIUM / LOW based on user impact scope.

6. Generate RECOMMENDED STEPS for the network engineer to resolve the issue.
   Steps should be specific, actionable, ordered by priority, and reference exact
   menu paths, CLI commands, or API calls where appropriate.

7. Identify any DATA GAPS — where missing telemetry limits your confidence.

IMPORTANT RULES:
- Do NOT auto-remediate. Only recommend. The engineer decides and executes.
- Be precise and technical. Avoid generic advice.
- If data shows no issue, say so clearly — do not fabricate problems.
- Reference specific values from the data (e.g. "SNR of 14 dB on SSID Corp-WiFi").
- If multiple issues coexist, rank them by user impact severity.

OUTPUT FORMAT: Respond ONLY with a valid JSON object. No markdown, no preamble.
Use exactly this schema:

{
  "rca_timestamp": "<ISO8601>",
  "overall_severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "issue_detected": true|false,
  "executive_summary": "<2–3 sentence non-technical summary>",
  "root_cause": {
    "domain": "AUTHENTICATION|RF_WIRELESS|APPLICATION|DHCP_DNS|MULTIPLE|NONE",
    "description": "<detailed technical description of root cause>",
    "confidence": "HIGH|MEDIUM|LOW",
    "supporting_evidence": ["<evidence point 1>", "<evidence point 2>", ...]
  },
  "contributing_factors": [
    {
      "domain": "<domain>",
      "description": "<description>",
      "severity": "HIGH|MEDIUM|LOW"
    }
  ],
  "affected_scope": {
    "estimated_users_impacted": "<number or range or 'Unknown'>",
    "affected_ssids": ["<ssid1>", ...],
    "affected_aps": ["<ap1>", ...],
    "affected_sites": ["<site1>", ...]
  },
  "recommended_steps": [
    {
      "priority": 1,
      "action": "<short action title>",
      "detail": "<full technical instruction with exact steps/commands>",
      "system": "ClearPass|Central|UXI|Switch|AP|DNS|DHCP|General",
      "estimated_time": "<e.g. 5 min | 30 min | 2 hrs>"
    }
  ],
  "data_gaps": ["<gap 1>", "<gap 2>"],
  "next_check_recommendation": "<when and what to recheck after remediation>"
}
"""

# ── Engine ─────────────────────────────────────────────────────────────────────

class RCAEngine:
    """Orchestrates the Claude AI root cause analysis."""

    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError("ANTHROPIC_API_KEY is not set.")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = os.getenv("RCA_MODEL", "claude-sonnet-4-6")
        self.max_tokens = int(os.getenv("RCA_MAX_TOKENS", 8192))

    def analyse(
        self,
        uxi_data: dict,
        central_data: dict,
        clearpass_data: dict,
        trigger_context: str = "scheduled_poll",
    ) -> dict:
        """
        Send all telemetry to Claude and return structured RCA dict.

        Args:
            uxi_data:        Output from UXICollector.collect_all()
            central_data:    Output from CentralCollector.collect_all()
            clearpass_data:  Output from ClearPassCollector.collect_all()
            trigger_context: How this run was triggered (for Claude's awareness)

        Returns:
            Parsed RCA dict matching the schema in SYSTEM_PROMPT.
        """
        telemetry_payload = {
            "trigger_context": trigger_context,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "uxi": uxi_data,
            "aruba_central": central_data,
            "clearpass": clearpass_data,
        }

        user_message = f"""
Please perform a full-stack root cause analysis on the following network telemetry
collected from the campus WLAN environment. All three data sources cover the same
lookback window.

TELEMETRY DATA:
```json
{json.dumps(telemetry_payload, indent=2, default=str)}
```

Apply your diagnostic reasoning across all failure domains:
- Authentication (ClearPass data)
- RF/Wireless (Aruba Central AP and client data)
- Application performance (UXI test results and app metrics)
- DHCP/DNS (UXI synthetic test failures)

Return ONLY the JSON RCA object as specified. No additional text.
"""

        logger.info(f"RCA Engine: sending telemetry to Claude ({self.model})...")

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise

        raw_text = response.content[0].text.strip()

        # Strip any accidental markdown fences
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]

        try:
            rca_result = json.loads(raw_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse RCA JSON: {e}\nRaw: {raw_text[:500]}")
            raise

        logger.info(
            f"RCA complete: severity={rca_result.get('overall_severity')} "
            f"| issue={rca_result.get('issue_detected')} "
            f"| domain={rca_result.get('root_cause', {}).get('domain')}"
        )
        return rca_result
