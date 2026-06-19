# triggers/scheduler.py
import os
import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

CRON_EXPR = os.getenv("POLL_CRON", "*/10 * * * *")  # every 10 min default


def start_scheduler(workflow_fn):
    """Start the APScheduler cron-based polling loop."""
    scheduler = BlockingScheduler()

    # Parse cron expression (minute, hour, day, month, day_of_week)
    parts = CRON_EXPR.split()
    trigger = CronTrigger(
        minute=parts[0], hour=parts[1],
        day=parts[2], month=parts[3], day_of_week=parts[4]
    )

    scheduler.add_job(
        lambda: workflow_fn("scheduled_poll"),
        trigger=trigger,
        id="rca_poll",
        name="Aruba RCA Scheduled Poll",
        max_instances=1,       # prevent overlapping runs
        coalesce=True,
    )

    logger.info(f"Scheduler started — cron: '{CRON_EXPR}' (UTC)")
    scheduler.start()
