"""RQ glue. `run_scan_job` is what the worker process executes."""

from collections.abc import Callable

from redis import Redis
from rq import Queue
from sqlmodel import Session

from ..config import get_settings
from ..db import init_db, make_engine
from ..engines.registry import register_from_settings
from .service import execute_scan

QUEUE_NAME = "aeroscan-scans"
JOB_TIMEOUT_SECONDS = 3600


def make_queue(connection: Redis | None = None, is_async: bool = True) -> Queue:
    conn = connection or Redis.from_url(get_settings().redis_url)
    return Queue(QUEUE_NAME, connection=conn, is_async=is_async)


def enqueuer(queue: Queue) -> Callable[[str], None]:
    def enqueue(job_id: str) -> None:
        # job id doubles as the rq id so a double-enqueue is visible, not silent
        queue.enqueue(run_scan_job, job_id, job_id=f"scan-{job_id}", job_timeout=JOB_TIMEOUT_SECONDS)

    return enqueue


def run_scan_job(job_id: str) -> str:
    settings = get_settings()
    register_from_settings(settings)
    engine = make_engine(settings.database_url)
    init_db(engine)
    with Session(engine) as session:
        job = execute_scan(session, job_id, settings.snapshot_key,
                           proxy_bind=(settings.gate_proxy_bind, settings.gate_proxy_port))
        return job.state.value
