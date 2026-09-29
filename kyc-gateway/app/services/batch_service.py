"""
Batch registration processing (synchronous simulation of an async job),
v2.0.0: individual and corporate.

In a real deployment this would enqueue records for background processing
and update job status incrementally. For this stub, records are processed
synchronously and the job is marked completed immediately; the job_id /
polling contract described in the spec is preserved so client integration
code does not need to change later. A batch.completed webhook (if
configured) is fired via FastAPI BackgroundTasks so it never blocks the
202 response.

Every record carries its own verification_reference and is validated
independently — the spec is explicit that identity verification is real
time and per subscriber, never batched, and no biometric ever appears here.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import BackgroundTasks

from app.core.config import settings
from app.schemas.kyc import (
    BatchAcceptedResponse,
    BatchCompletedEvent,
    BatchStatusResponse,
    CorporateBatchRegistrationRequest,
    IndividualBatchRegistrationRequest,
)
from app.services.exceptions import KycServiceError
from app.services.db import store
from app.services.webhook_service import send_batch_completed


def _fire_webhook(job, background_tasks: Optional[BackgroundTasks]) -> None:
    if background_tasks is None:
        return
    event = BatchCompletedEvent(
        job_id=job.job_id,
        status=job.status,
        total_records=job.total_records,
        processed_records=job.processed_records,
        successful_records=job.successful_records,
        failed_records=job.failed_records,
        timestamp=datetime.now(timezone.utc),
    )
    background_tasks.add_task(send_batch_completed, event)


def _check_idempotency(idempotency_key: Optional[str]) -> Optional[str]:
    if not idempotency_key:
        return None
    existing_job_id = store.get_idempotent_job(idempotency_key)
    if existing_job_id:
        raise KycServiceError(409, "DUPLICATE_REQUEST", "Duplicate batch submission")
    return idempotency_key


def submit_individual_batch(
    payload: IndividualBatchRegistrationRequest, mno: str,
    idempotency_key: Optional[str] = None, background_tasks: Optional[BackgroundTasks] = None,
) -> BatchAcceptedResponse:
    if len(payload.records) > settings.MAX_BATCH_SIZE:
        raise KycServiceError(
            422, "INVALID_PAYLOAD",
            f"Batch exceeds maximum size of {settings.MAX_BATCH_SIZE} records",
        )
    _check_idempotency(idempotency_key)

    job = store.create_batch_job(total_records=len(payload.records), kind="individual", prefix="batch")
    if idempotency_key:
        store.record_idempotency_key(idempotency_key, job.job_id)
    store.set_batch_status(job.job_id, "processing")

    for record in payload.records:
        if store.is_active_registration(record.msisdn):
            store.append_batch_result(
                job.job_id, record.msisdn, "rejected", "DUPLICATE_REQUEST",
                record.verification_reference, "SIM already registered", success=False,
            )
            continue

        error = store.validate_reference(record.verification_reference, record.id_type, record.id_number)
        if error:
            store.append_batch_result(
                job.job_id, record.msisdn, "rejected", error,
                record.verification_reference, None, success=False,
            )
            continue

        count = store.individual_ownership_count(record.id_type, record.id_number)
        limit = store.resolve_limit(
            f"individual:{record.id_number}", settings.GLOBAL_INDIVIDUAL_OWNERSHIP_LIMIT
        )
        if count >= limit:
            store.append_batch_result(
                job.job_id, record.msisdn, "rejected", "LIMIT_EXCEEDED",
                record.verification_reference, "Subscriber has exceeded SIM ownership limit",
                success=False,
            )
            continue

        store.upsert_registration(
            msisdn=record.msisdn, kind="individual", id_type=record.id_type,
            id_number=record.id_number, mno=mno, surname=record.surname,
            given_name=record.given_name, gender=record.gender,
        )
        store.append_batch_result(
            job.job_id, record.msisdn, "accepted", "REGISTRATION_ACCEPTED",
            record.verification_reference, None, success=True,
        )

    store.set_batch_status(job.job_id, "completed")
    job = store.get_batch_job(job.job_id)
    _fire_webhook(job, background_tasks)

    return BatchAcceptedResponse(
        status="accepted", job_id=job.job_id, message="Batch accepted for processing"
    )


def submit_corporate_batch(
    payload: CorporateBatchRegistrationRequest, mno: str,
    idempotency_key: Optional[str] = None, background_tasks: Optional[BackgroundTasks] = None,
) -> BatchAcceptedResponse:
    if len(payload.records) > settings.MAX_BATCH_SIZE:
        raise KycServiceError(
            422, "INVALID_PAYLOAD",
            f"Batch exceeds maximum size of {settings.MAX_BATCH_SIZE} records",
        )
    _check_idempotency(idempotency_key)

    job = store.create_batch_job(total_records=len(payload.records), kind="corporate", prefix="cbatch")
    if idempotency_key:
        store.record_idempotency_key(idempotency_key, job.job_id)
    store.set_batch_status(job.job_id, "processing")

    for record in payload.records:
        if store.is_active_registration(record.msisdn):
            store.append_batch_result(
                job.job_id, record.msisdn, "rejected", "DUPLICATE_REQUEST",
                record.verification_reference, "Corporate SIM already registered", success=False,
            )
            continue

        # Organisation-bound, same as the single-record endpoint — see
        # registration_service.register_corporate for the spec citation.
        error = store.validate_reference(
            record.verification_reference, record.id_type, record.registration_number
        )
        if error:
            store.append_batch_result(
                job.job_id, record.msisdn, "rejected", error,
                record.verification_reference, None, success=False,
            )
            continue

        count = store.corporate_ownership_count(record.registration_number)
        limit = store.resolve_limit(
            f"corporate:{record.registration_number}", settings.GLOBAL_CORPORATE_OWNERSHIP_LIMIT
        )
        if count >= limit:
            store.append_batch_result(
                job.job_id, record.msisdn, "rejected", "LIMIT_EXCEEDED",
                record.verification_reference, "Subscriber has exceeded SIM ownership limit",
                success=False,
            )
            continue

        rep = record.representative
        store.upsert_registration(
            msisdn=record.msisdn, kind="corporate", id_type=record.id_type,
            id_number=record.registration_number, mno=mno, surname=rep.surname,
            given_name=rep.given_name,
        )
        store.append_batch_result(
            job.job_id, record.msisdn, "accepted", "REGISTRATION_ACCEPTED",
            record.verification_reference, None, success=True,
        )

    store.set_batch_status(job.job_id, "completed")
    job = store.get_batch_job(job.job_id)
    _fire_webhook(job, background_tasks)

    return BatchAcceptedResponse(
        status="accepted", job_id=job.job_id, message="Batch accepted for processing"
    )


def get_batch_status(job_id: str) -> BatchStatusResponse:
    job = store.get_batch_job(job_id)
    if job is None:
        raise KycServiceError(404, "NOT_FOUND", "Job not found")

    return BatchStatusResponse(
        job_id=job.job_id,
        status=job.status,
        total_records=job.total_records,
        processed_records=job.processed_records,
        successful_records=job.successful_records,
        failed_records=job.failed_records,
        results=job.results,
    )
