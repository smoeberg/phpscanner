"""Persistent PostgreSQL-backed scan worker.

Run one or more instances with: python -m app.worker
Jobs are claimed with SKIP LOCKED and fenced by a per-claim token. Expired
claims are recoverable after a worker crash.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets

import psycopg

from app import main

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("scanner.worker")

POLL_SECONDS = float(os.getenv("SCAN_WORKER_POLL_SECONDS", "2"))
JOB_LEASE_SECONDS = 90
MAX_ATTEMPTS = 3


def claim_next_job():
    token = secrets.token_urlsafe(32)
    with main.db_connect() as conn:
        conn.execute(
            """
            UPDATE scan_jobs
            SET status = 'failed', finished_at = now(), lease_until = NULL,
                lease_token = NULL, last_error = 'Worker lease expired after maximum attempts',
                updated_at = now()
            WHERE status = 'running' AND lease_until <= now() AND attempts >= %s
            """,
            (MAX_ATTEMPTS,),
        )
        return conn.execute(
            """
            WITH candidate AS (
                SELECT id
                FROM scan_jobs
                WHERE attempts < %s
                  AND available_at <= now()
                  AND (
                    status = 'queued'
                    OR (status = 'running' AND lease_until <= now())
                  )
                ORDER BY created_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE scan_jobs AS j
            SET status = 'running',
                attempts = j.attempts + 1,
                started_at = COALESCE(j.started_at, now()),
                lease_until = now() + (%s * interval '1 second'),
                lease_token = %s,
                updated_at = now()
            FROM candidate
            WHERE j.id = candidate.id
            RETURNING j.id, j.domain_id, j.attempts, j.lease_token
            """,
            (MAX_ATTEMPTS, JOB_LEASE_SECONDS, token),
        ).fetchone()


def defer_job(job_id: int, token: str) -> None:
    with main.db_connect() as conn:
        conn.execute(
            """
            UPDATE scan_jobs
            SET status = 'queued', attempts = GREATEST(attempts - 1, 0),
                available_at = now() + interval '5 seconds',
                lease_until = NULL, lease_token = NULL, updated_at = now()
            WHERE id = %s AND status = 'running' AND lease_token = %s
            """,
            (job_id, token),
        )


def fail_job(job_id: int, token: str, message: str, *, retry: bool) -> None:
    with main.db_connect() as conn:
        conn.execute(
            """
            UPDATE scan_jobs
            SET status = CASE WHEN %s AND attempts < %s THEN 'queued' ELSE 'failed' END,
                available_at = CASE WHEN %s AND attempts < %s
                    THEN now() + LEAST(60, 5 * power(2, GREATEST(attempts - 1, 0))) * interval '1 second'
                    ELSE available_at END,
                finished_at = CASE WHEN %s AND attempts < %s THEN NULL ELSE now() END,
                lease_until = NULL, lease_token = NULL, last_error = %s,
                updated_at = now()
            WHERE id = %s AND status = 'running' AND lease_token = %s
            """,
            (retry, MAX_ATTEMPTS, retry, MAX_ATTEMPTS, retry, MAX_ATTEMPTS,
             message[:500], job_id, token),
        )


def persist_result(job_id: int, domain_id: int, token: str, result: dict) -> None:
    with main.db_connect() as conn:
        saved = conn.execute(
            """
            INSERT INTO scans(
                domain_id, status_code, final_url, server_header, powered_by,
                php_indicator, version_observed, confidence, notes, job_id
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (job_id) DO NOTHING
            RETURNING id
            """,
            (
                domain_id, result["status_code"], result["final_url"],
                result["server_header"], result["powered_by"],
                result["php_indicator"], result["version_observed"],
                result["confidence"], result["notes"], job_id,
            ),
        ).fetchone()
        if saved:
            scan_id = saved[0]
        else:
            existing = conn.execute(
                "SELECT id FROM scans WHERE job_id = %s",
                (job_id,),
            ).fetchone()
            if not existing:
                raise RuntimeError("Scan result could not be reconciled")
            scan_id = existing[0]
        updated = conn.execute(
            """
            UPDATE scan_jobs
            SET status = 'succeeded', scan_id = %s, finished_at = now(),
                lease_until = NULL, lease_token = NULL, last_error = NULL,
                updated_at = now()
            WHERE id = %s AND status = 'running' AND lease_token = %s
            RETURNING id
            """,
            (scan_id, job_id, token),
        ).fetchone()
        if not updated:
            raise RuntimeError("Scan job lease was lost before completion")


async def process_job(job) -> None:
    job_id, domain_id, attempts, token = job
    slot = None
    try:
        with main.db_connect() as conn:
            domain = conn.execute(
                "SELECT domain, verified_at FROM domains WHERE id = %s",
                (domain_id,),
            ).fetchone()
        if not domain or domain[1] is None:
            fail_job(job_id, token, "Domain verification is missing", retry=False)
            return

        try:
            slot = main.reserve_scan_capacity(domain_id)
        except main.ScanAuthorizationError:
            fail_job(job_id, token, "No current authorization for scan target", retry=False)
            return
        if slot is None:
            defer_job(job_id, token)
            return

        async with asyncio.timeout(main.SCAN_EXECUTION_DEADLINE_SECONDS):
            result = await main.probe(domain[0])
        persist_result(job_id, domain_id, token, result)
    except TimeoutError:
        fail_job(job_id, token, "Scan execution deadline exceeded", retry=True)
    except Exception:
        logger.exception("Scan job %s failed", job_id)
        fail_job(job_id, token, "Scan execution failed; see worker logs", retry=True)
    finally:
        if slot is not None:
            try:
                main.release_scan_capacity(*slot)
            except Exception:
                logger.exception("Could not release scan capacity for job %s", job_id)


async def run_worker() -> None:
    logger.info("Persistent scan worker started")
    while True:
        try:
            job = claim_next_job()
            if job:
                await process_job(job)
            else:
                await asyncio.sleep(POLL_SECONDS)
        except (psycopg.Error, OSError):
            logger.exception("Worker database operation failed")
            await asyncio.sleep(POLL_SECONDS)
        except Exception:
            logger.exception("Unexpected worker loop failure")
            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(run_worker())
