"""S3 storage verification routes."""

import logging
from fastapi import APIRouter

from app.schemas.aws import StorageVerification
from app.services.report_storage import get_report_storage

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/storage", tags=["S3 Storage"])


@router.post("/verify", response_model=StorageVerification)
def verify_storage() -> StorageVerification:
    """Verify write, read, delete, and SSE-S3 encryption on the report S3 bucket."""
    storage = get_report_storage()
    result = storage.verify_s3_storage()

    # Populate convenience fields for frontend compatibility
    result.bucket = result.bucket_name
    result.success = (result.status == "PASSED")
    result.details = {
        "write_access": result.write_access,
        "read_access": result.read_access,
        "delete_access": result.delete_access,
        "encryption_working": result.encryption_working,
    }
    return result

