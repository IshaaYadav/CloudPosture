"""S3 Report Storage Service - handles storing, retrieving, and verifying scan reports."""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from botocore.exceptions import ClientError, NoCredentialsError

from app.aws.session import get_session_manager
from app.config import get_settings
from app.schemas.aws import StorageVerification

logger = logging.getLogger(__name__)

# Base S3 prefix for all scanner artifacts
S3_PREFIX = "cloud-posture-scanner"


class S3ReportStorage:
    """Manages report persistence in Amazon S3 using SSE-S3 encryption."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._session_manager = get_session_manager()
        self._bucket_region: Optional[str] = None

    @property
    def bucket_name(self) -> str:
        """Configured S3 bucket name."""
        return self._settings.POSTURE_RESULTS_BUCKET

    def get_bucket_region(self) -> str:
        """Detect and return the actual AWS region of the configured report bucket using GetBucketLocation.

        Does not assume the bucket resides in the default AWS_REGION.
        """
        if self._bucket_region:
            return self._bucket_region

        try:
            # Query location using default session S3 client
            base_client = self._session_manager.get_client("s3")
            resp = base_client.get_bucket_location(Bucket=self.bucket_name)
            location = resp.get("LocationConstraint")
            if location is None or location == "":
                region = "us-east-1"
            elif location == "EU":
                region = "eu-west-1"
            else:
                region = location
            self._bucket_region = region
            logger.info(f"Detected actual region for bucket '{self.bucket_name}': {region}")
            return region
        except Exception as e:
            logger.warning(
                f"Could not determine bucket location for '{self.bucket_name}' via GetBucketLocation, "
                f"falling back to configured AWS_REGION ({self._settings.AWS_REGION}): {e}"
            )
            return self._settings.AWS_REGION

    def _get_s3_client(self) -> Any:
        """Get an authenticated boto3 S3 client targeted at the bucket's actual detected region."""
        region = self.get_bucket_region()
        return self._session_manager.get_client("s3", region_name=region)

    def _build_scan_key(self, scan_id: str, timestamp_str: str) -> str:
        """Construct the partitioned S3 key for a scan report.

        Format:
            cloud-posture-scanner/scans/YYYY/MM/DD/scan_<scan_id>.json
        """
        try:
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)

        year = dt.strftime("%Y")
        month = dt.strftime("%m")
        day = dt.strftime("%d")

        return f"{S3_PREFIX}/scans/{year}/{month}/{day}/scan_{scan_id}.json"

    def _build_latest_key(self) -> str:
        """Construct the S3 key for the pointer to the latest scan."""
        return f"{S3_PREFIX}/latest/latest_scan.json"

    def upload_scan_report(self, report_data: dict[str, Any]) -> str:
        """Upload a scan report to S3 and update the latest pointer.

        Uses SSE-S3 encryption (ServerSideEncryption='AES256') and S3 Standard storage.

        Args:
            report_data: Dictionary representing the full scan report.

        Returns:
            The primary S3 object key where the report was stored.

        Raises:
            ValueError: If credentials or bucket configuration are missing.
            ClientError: If upload fails.
        """
        s3_client = self._get_s3_client()
        scan_id = report_data.get("scan_id", str(uuid.uuid4()))
        timestamp = report_data.get("timestamp", datetime.now(timezone.utc).isoformat())

        scan_key = self._build_scan_key(scan_id, timestamp)
        latest_key = self._build_latest_key()

        payload = json.dumps(report_data, default=str, indent=2).encode("utf-8")

        logger.info(f"Uploading scan report {scan_id} to s3://{self.bucket_name}/{scan_key}")

        # 1. Upload the dated immutable report
        s3_client.put_object(
            Bucket=self.bucket_name,
            Key=scan_key,
            Body=payload,
            ContentType="application/json",
            ServerSideEncryption="AES256",
            StorageClass="STANDARD",
        )

        # 2. Update latest pointer
        try:
            s3_client.put_object(
                Bucket=self.bucket_name,
                Key=latest_key,
                Body=payload,
                ContentType="application/json",
                ServerSideEncryption="AES256",
                StorageClass="STANDARD",
            )
            logger.info(f"Updated latest scan report at s3://{self.bucket_name}/{latest_key}")
        except Exception as e:
            logger.warning(f"Failed to update latest scan pointer in S3: {e}")

        return scan_key

    def get_latest_scan(self) -> Optional[dict[str, Any]]:
        """Retrieve the latest scan report from S3.

        Returns:
            Parsed report dictionary or None if not found.
        """
        s3_client = self._get_s3_client()
        latest_key = self._build_latest_key()

        try:
            response = s3_client.get_object(Bucket=self.bucket_name, Key=latest_key)
            content = response["Body"].read().decode("utf-8")
            return json.loads(content)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("NoSuchKey", "404"):
                logger.info("No latest scan found in S3")
                return None
            logger.error(f"Error fetching latest scan from S3: {e}")
            raise

    def get_scan_by_id(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Find and retrieve a specific scan report by scan_id from S3.

        Searches under the cloud-posture-scanner/scans/ prefix.

        Returns:
            Parsed report dict or None if not found.
        """
        s3_client = self._get_s3_client()
        prefix = f"{S3_PREFIX}/scans/"

        paginator = s3_client.get_paginator("list_objects_v2")
        target_filename = f"scan_{scan_id}.json"

        try:
            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj.get("Key", "")
                    if key.endswith(target_filename):
                        response = s3_client.get_object(Bucket=self.bucket_name, Key=key)
                        content = response["Body"].read().decode("utf-8")
                        return json.loads(content)
            logger.info(f"Scan with ID '{scan_id}' not found in S3 bucket {self.bucket_name}")
            return None
        except ClientError as e:
            logger.error(f"Error searching for scan {scan_id} in S3: {e}")
            raise

    def list_scan_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """List past scans stored in S3, ordered by newest first.

        Returns:
            List of lightweight history summaries.
        """
        s3_client = self._get_s3_client()
        prefix = f"{S3_PREFIX}/scans/"
        history: list[dict[str, Any]] = []

        try:
            paginator = s3_client.get_paginator("list_objects_v2")
            all_keys: list[str] = []

            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj.get("Key", "")
                    if key.endswith(".json") and "scan_" in key:
                        all_keys.append(key)

            # Sort descending by key (keys include YYYY/MM/DD which sorts chronologically)
            all_keys.sort(reverse=True)
            target_keys = all_keys[:limit]

            for key in target_keys:
                try:
                    response = s3_client.get_object(Bucket=self.bucket_name, Key=key)
                    data = json.loads(response["Body"].read().decode("utf-8"))

                    summary = data.get("summary") or {}
                    score_info = data.get("posture_score") or {}
                    checks = data.get("check_results") or []

                    passed = score_info.get("passed", 0)
                    failed = score_info.get("failed", 0)
                    errors = score_info.get("errors", 0)
                    if not passed and not failed and not errors:
                        for c in checks:
                            st = c.get("status")
                            if st == "PASS":
                                passed += 1
                            elif st == "FAIL":
                                failed += 1
                            elif st == "ERROR":
                                errors += 1

                    score_val = score_info.get("score")
                    score_display = f"{score_val}%" if score_val is not None else "N/A"

                    history.append({
                        "scan_id": data.get("scan_id", ""),
                        "timestamp": data.get("timestamp", ""),
                        "account_id": data.get("account_id", ""),
                        "total_resources": len(data.get("instances", [])) + len(data.get("buckets", [])),
                        "passed": passed,
                        "failed": failed,
                        "errors": errors,
                        "score": score_val,
                        "score_display": score_display,
                        "s3_key": key,
                        "storage_key": key,
                    })
                except Exception as ex:
                    logger.warning(f"Could not parse scan report at {key}: {ex}")

            return history
        except ClientError as e:
            logger.error(f"Error listing scan history from S3: {e}")
            raise

    def verify_s3_storage(self) -> StorageVerification:
        """Run a dedicated end-to-end verification of S3 report storage.

        Steps:
            1. Verify bucket exists and is accessible.
            2. Write a small temporary test object with SSE-S3 encryption.
            3. Read back the test object and verify content.
            4. Delete the temporary test object.
            5. Return detailed StorageVerification result.
        """
        now = datetime.now(timezone.utc).isoformat()
        test_id = str(uuid.uuid4())[:8]
        test_key = f"{S3_PREFIX}/_tests/verification_{test_id}.json"
        test_payload = json.dumps({
            "test_id": test_id,
            "timestamp": now,
            "action": "storage_verification",
        }).encode("utf-8")

        write_ok = False
        read_ok = False
        delete_ok = False
        sse_ok = False

        s3_client = None
        try:
            s3_client = self._get_s3_client()
        except Exception as e:
            return StorageVerification(
                bucket_name=self.bucket_name,
                write_access=False,
                read_access=False,
                delete_access=False,
                encryption_working=False,
                status="FAILED",
                message=f"AWS connection error: {str(e)}",
                timestamp=now,
            )

        # Step 1 & 2: Put test object
        try:
            put_resp = s3_client.put_object(
                Bucket=self.bucket_name,
                Key=test_key,
                Body=test_payload,
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
            write_ok = True
            sse_header = put_resp.get("ServerSideEncryption", "")
            sse_ok = (sse_header == "AES256") or ("ServerSideEncryption" in put_resp)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"]["Message"]
            return StorageVerification(
                bucket_name=self.bucket_name,
                write_access=False,
                read_access=False,
                delete_access=False,
                encryption_working=False,
                status="FAILED",
                message=f"Write test failed ({code}): {msg}",
                timestamp=now,
            )

        # Step 3: Get test object
        try:
            get_resp = s3_client.get_object(Bucket=self.bucket_name, Key=test_key)
            body = get_resp["Body"].read()
            data = json.loads(body.decode("utf-8"))
            if data.get("test_id") == test_id:
                read_ok = True
                if get_resp.get("ServerSideEncryption") == "AES256":
                    sse_ok = True
        except Exception as e:
            logger.error(f"Failed to read verification object: {e}")

        # Step 4: Delete test object
        try:
            s3_client.delete_object(Bucket=self.bucket_name, Key=test_key)
            delete_ok = True
        except Exception as e:
            logger.error(f"Failed to delete verification object: {e}")

        all_ok = write_ok and read_ok and delete_ok
        status = "PASSED" if all_ok else "PARTIAL"
        detected_region = self.get_bucket_region()
        message = (
            f"Successfully verified S3 bucket '{self.bucket_name}' (region: {detected_region}) "
            f"for read, write, and SSE-S3 encryption."
            if all_ok
            else "S3 storage test encountered issues during verification."
        )

        return StorageVerification(
            bucket_name=self.bucket_name,
            write_access=write_ok,
            read_access=read_ok,
            delete_access=delete_ok,
            encryption_working=sse_ok,
            status=status,
            message=message,
            timestamp=now,
            details={"detected_region": detected_region},
        )


# Singleton
_storage: Optional[S3ReportStorage] = None


def get_report_storage() -> S3ReportStorage:
    """Return the singleton S3ReportStorage instance."""
    global _storage
    if _storage is None:
        _storage = S3ReportStorage()
    return _storage

