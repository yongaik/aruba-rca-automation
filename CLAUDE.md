# CLAUDE.md — Aruba RCA Automation Project

## Project Purpose
This project automates root cause analysis (RCA) of user-experience issues on a campus
HPE Aruba wireless/wired network. It collects telemetry from three systems — UXI, Aruba
Central, and ClearPass — and uses Claude AI to perform cross-domain RCA, then produces
Markdown + HTML reports and a Slack notification.

## Environment
- Python 3.11+, virtual environment at ./venv
- All secrets in .env (never commit this file)
- Config in config.yaml

## Key Commands

### Run a single on-demand RCA
```bash
source venv/bin/activate
python main.py run
```

### Start scheduled polling (every 10 min)
```bash
python main.py schedule
```

### Start webhook listener only
```bash
python main.py webhook
```

### Start scheduler + webhook together
```bash
python main.py schedule --also-webhook
```

### Listen to Slack for UXI alert notifications (Socket Mode)
```bash
python main.py slack-listen
```

### Run tests with mock data
```bash
pytest tests/ -v
```

## Architecture Summary

```
main.py
 ├── UXICollector      → collectors/uxi_collector.py
 ├── CentralCollector  → collectors/central_collector.py
 ├── ClearPassCollector→ collectors/clearpass_collector.py
 ├── RCAEngine         → analysis/rca_engine.py  (calls Claude API)
 ├── generate_markdown → reports/markdown_reporter.py
 ├── generate_html     → reports/html_reporter.py
 └── post_to_slack     → reports/slack_notifier.py
Triggers:
 ├── triggers/scheduler.py       (APScheduler cron)
 └── triggers/webhook_server.py  (Flask, port 5001)
```

## Failure Domains Covered
1. AUTHENTICATION — ClearPass RADIUS 802.1X/MAB failures
2. RF_WIRELESS    — AP health, SNR, channel utilization, noise
3. APPLICATION    — UXI test failure rates, latency, packet loss
4. DHCP_DNS      — UXI synthetic DHCP/DNS test results

## Key Environment Variables
See .env.example for all variables. Critical ones:
- UXI_API_TOKEN, CENTRAL_CLIENT_ID, CENTRAL_CLIENT_SECRET, CENTRAL_CUSTOMER_ID
- CPPM_HOST, CPPM_CLIENT_ID, CPPM_CLIENT_SECRET
- ANTHROPIC_API_KEY
- SLACK_WEBHOOK_URL
- POLL_CRON (default: "*/10 * * * *")
- LOOKBACK_MINUTES (default: 30)

## Thresholds (adjustable in config.yaml)
- UXI test failure rate: >20% triggers alert
- Client SNR: <20 dB flags poor wireless
- App latency: >200ms flags degradation
- Auth failure rate: >10% triggers alert

## Output
All reports saved to ./output/<YYYYMMDD_HHMMSS>/
- rca_report.md
- rca_report.html
Log file: rca_workflow.log

## Webhook Setup
Configure in Aruba Central (Notifications → Webhooks):
  URL: http://<your-server-ip>:5001/webhook/aruba
  Secret: value of WEBHOOK_SECRET in your .env

Configure in UXI (Settings → Webhooks):
  URL: http://<your-server-ip>:5001/webhook/aruba

## Common Claude Code Tasks
- "Run an RCA analysis now" → python main.py run
- "Show the latest report" → cat output/<latest>/rca_report.md
- "Check for auth failures in the last hour" → adjust LOOKBACK_MINUTES=60, run
- "Show me the raw UXI data" → python -c "from collectors.uxi_collector import UXICollector; import json; print(json.dumps(UXICollector().collect_all(), indent=2))"
- "Test without real APIs" → use mock data in tests/mock_data/
