"""
Registration endpoints, v2.0.0:
  POST   /individual_registrations
  POST   /corporate_registrations
  PUT    /individual_registrations/{msisdn}
  PATCH  /individual_registrations/{msisdn}
  POST   /individual_registrations/batch
  GET    /individual_registrations/batch/{job_id}
  POST   /corporate_registrations/batch
  GET    /corporate_registrations/batch/{job_id}
  POST   /individual_registrations/{msisdn}/ownership_change
  POST   /individual_registrations/{msisdn}/deregistration
"""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException

from app.api.deps.auth import require_api_key
from app.schemas.kyc import (
    AmendmentRequest,
    AmendmentResponse,
    BatchAcceptedResponse,
    BatchStatusResponse,
    CorporateBatchRegistrationRequest,
    CorporateRegistrationRequest,
    DeregistrationRequest,
    DeregistrationResponse,
    IndividualBatchRegistrationRequest,
    IndividualRegistrationRecord,
    IndividualRegistrationRequest,
    OwnershipChangeRequest,
    OwnershipChangeResponse,
    StandardResponse,
)
from app.services.exceptions import KycServiceError
from app.services import batch_service, registration_service

router = APIRouter(tags=["Registration"])


def _raise(exc: KycServiceError):
    raise HTTPException(
        status_code=exc.status_code,
        detail={"status": "error", "error_code": exc.error_code, "message": exc.message},
    )


@router.post(
    "/individual_registrations",
    response_model=StandardResponse,
    operation_id="createIndividualRegistration",
    summary="Register individual SIM",
)
async def create_individual_registration(
    payload: IndividualRegistrationRequest, mno: str = Depends(require_api_key)
):
    try:
        return registration_service.register_individual(payload, mno)
    except KycServiceError as exc:
        _raise(exc)


@router.post(
    "/corporate_registrations",
    response_model=StandardResponse,
    operation_id="createCorporateRegistration",
    summary="Register corporate SIM",
)
async def create_corporate_registration(
    payload: CorporateRegistrationRequest, mno: str = Depends(require_api_key)
):
    try:
        return registration_service.register_corporate(payload, mno)
    except KycServiceError as exc:
        _raise(exc)


@router.put(
    "/individual_registrations/{msisdn}",
    response_model=StandardResponse,
    operation_id="updateIndividualRegistration",
    summary="Update subscriber registration",
)
async def update_individual_registration(
    msisdn: str, payload: IndividualRegistrationRecord, mno: str = Depends(require_api_key)
):
    try:
        return registration_service.update_individual_registration(msisdn, payload, mno)
    except KycServiceError as exc:
        _raise(exc)


@router.patch(
    "/individual_registrations/{msisdn}",
    response_model=AmendmentResponse,
    operation_id="amendIndividualRegistration",
    summary="Amend subscriber details",
)
async def amend_individual_registration(
    msisdn: str, payload: AmendmentRequest, mno: str = Depends(require_api_key)
):
    try:
        return registration_service.amend_individual_registration(msisdn, payload, mno)
    except KycServiceError as exc:
        _raise(exc)


@router.post(
    "/individual_registrations/{msisdn}/ownership_change",
    response_model=OwnershipChangeResponse,
    operation_id="changeIndividualOwnership",
    summary="Transfer a SIM to a new subscriber",
)
async def change_individual_ownership(
    msisdn: str, payload: OwnershipChangeRequest, mno: str = Depends(require_api_key)
):
    try:
        return registration_service.change_ownership(msisdn, payload, mno)
    except KycServiceError as exc:
        _raise(exc)


@router.post(
    "/individual_registrations/{msisdn}/deregistration",
    response_model=DeregistrationResponse,
    operation_id="deregisterIndividualRegistration",
    summary="End a SIM registration",
)
async def deregister_individual_registration(
    msisdn: str, payload: DeregistrationRequest, mno: str = Depends(require_api_key)
):
    try:
        return registration_service.deregister_individual(msisdn, payload, mno)
    except KycServiceError as exc:
        _raise(exc)


@router.post(
    "/individual_registrations/batch",
    response_model=BatchAcceptedResponse,
    status_code=202,
    operation_id="createIndividualBatchRegistration",
    summary="Submit batch SIM registrations",
)
async def create_individual_batch_registration(
    payload: IndividualBatchRegistrationRequest,
    background_tasks: BackgroundTasks,
    mno: str = Depends(require_api_key),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    try:
        return batch_service.submit_individual_batch(
            payload, mno, idempotency_key=idempotency_key, background_tasks=background_tasks
        )
    except KycServiceError as exc:
        _raise(exc)


@router.get(
    "/individual_registrations/batch/{job_id}",
    response_model=BatchStatusResponse,
    operation_id="getIndividualBatchStatus",
    summary="Retrieve batch processing status",
)
async def get_individual_batch_status(job_id: str, mno: str = Depends(require_api_key)):
    try:
        return batch_service.get_batch_status(job_id)
    except KycServiceError as exc:
        _raise(exc)


@router.post(
    "/corporate_registrations/batch",
    response_model=BatchAcceptedResponse,
    status_code=202,
    operation_id="createBatchCorporateRegistration",
    summary="Submit batch corporate registrations",
)
async def create_corporate_batch_registration(
    payload: CorporateBatchRegistrationRequest,
    background_tasks: BackgroundTasks,
    mno: str = Depends(require_api_key),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    try:
        return batch_service.submit_corporate_batch(
            payload, mno, idempotency_key=idempotency_key, background_tasks=background_tasks
        )
    except KycServiceError as exc:
        _raise(exc)


@router.get(
    "/corporate_registrations/batch/{job_id}",
    response_model=BatchStatusResponse,
    operation_id="getCorporateBatchStatus",
    summary="Retrieve corporate batch processing status",
)
async def get_corporate_batch_status(job_id: str, mno: str = Depends(require_api_key)):
    try:
        return batch_service.get_batch_status(job_id)
    except KycServiceError as exc:
        _raise(exc)
