"""IAM - account summary, credential reports, and root MFA verification."""

import csv
import io
import logging
import time
from typing import Any

from botocore.exceptions import ClientError, NoCredentialsError

from app.aws.session import get_session_manager

logger = logging.getLogger(__name__)


def get_account_summary() -> dict[str, Any]:
    """Retrieve the IAM account summary (SummaryMap).

    Calls iam:GetAccountSummary and returns the SummaryMap, which contains
    counts and quotas for IAM entities (users, groups, roles, policies,
    MFA devices, etc.).

    Returns:
        The SummaryMap dict from the API response. Keys include
        'Users', 'Groups', 'Roles', 'Policies', 'AccountMFAEnabled', etc.

    Raises:
        ValueError: If AWS credentials are not configured.
        ClientError: If the API call fails for reasons other than credentials.
    """
    session_manager = get_session_manager()
    try:
        iam_client = session_manager.get_client("iam")
        response = iam_client.get_account_summary()
        summary_map = response.get("SummaryMap", {})
        logger.info(f"IAM account summary retrieved: {len(summary_map)} keys")
        return summary_map
    except NoCredentialsError as e:
        logger.error(f"No AWS credentials found: {e}")
        raise ValueError(
            "No AWS credentials found. Cannot retrieve IAM account summary."
        ) from e
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]
        logger.error(f"Failed to get account summary: {error_code} - {error_msg}")
        raise


def get_credential_report() -> list[dict[str, str]]:
    """Generate and retrieve the IAM credential report.

    Calls iam:GenerateCredentialReport in a polling loop (up to 10 attempts,
    2-second sleep between attempts) until the report state is COMPLETE,
    then retrieves the report content, decodes it from bytes, and parses
    the CSV into a list of row dicts.

    Returns:
        List of dicts, one per IAM user row in the credential report.
        Returns an empty list if access is denied.

    Raises:
        ValueError: If AWS credentials are not configured.
        RuntimeError: If the report does not complete within the retry window.
    """
    session_manager = get_session_manager()
    try:
        iam_client = session_manager.get_client("iam")
    except (NoCredentialsError, ValueError) as e:
        logger.error(f"Cannot create IAM client: {e}")
        raise

    # Generate the credential report (may take multiple attempts)
    max_attempts = 10
    for attempt in range(1, max_attempts + 1):
        try:
            response = iam_client.generate_credential_report()
            state = response.get("State", "")
            logger.debug(
                f"Credential report generation attempt {attempt}/{max_attempts}: "
                f"state={state}"
            )
            if state == "COMPLETE":
                break
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.warning(
                    "Access denied when generating credential report. "
                    "Returning empty list."
                )
                return []
            logger.error(
                f"Error generating credential report: {error_code} - "
                f"{e.response['Error']['Message']}"
            )
            raise

        if attempt < max_attempts:
            time.sleep(2)
    else:
        logger.error(
            f"Credential report did not complete after {max_attempts} attempts"
        )
        raise RuntimeError(
            f"IAM credential report did not reach COMPLETE state after "
            f"{max_attempts} attempts."
        )

    # Retrieve the completed report
    try:
        report_response = iam_client.get_credential_report()
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("AccessDenied", "AccessDeniedException"):
            logger.warning(
                "Access denied when retrieving credential report. "
                "Returning empty list."
            )
            return []
        logger.error(
            f"Error retrieving credential report: {error_code} - "
            f"{e.response['Error']['Message']}"
        )
        raise

    # Decode and parse CSV content
    content_bytes: bytes = report_response.get("Content", b"")
    content_str = content_bytes.decode("utf-8")

    reader = csv.DictReader(io.StringIO(content_str))
    rows = list(reader)
    logger.info(f"Credential report parsed: {len(rows)} user entries")
    return rows


def check_root_mfa() -> dict[str, Any]:
    """Check whether MFA is enabled for the AWS root account.

    Uses two evidence sources:
      1. IAM AccountSummary: checks if AccountMFAEnabled == 1.
      2. Credential report: looks for the '<root_account>' user row and
         checks if mfa_active == 'true'.

    Returns:
        Dict with:
            mfa_enabled (bool): True if MFA is confirmed enabled from any source.
            evidence (list[str]): Human-readable evidence strings.
            account_summary_available (bool): Whether account summary was readable.
            credential_report_available (bool): Whether credential report was readable.
    """
    mfa_enabled = False
    evidence: list[str] = []
    account_summary_available = False
    credential_report_available = False

    # Check via Account Summary
    try:
        summary = get_account_summary()
        account_summary_available = True
        account_mfa_enabled = summary.get("AccountMFAEnabled", 0)
        if account_mfa_enabled == 1:
            mfa_enabled = True
            evidence.append(
                "AccountSummary: AccountMFAEnabled = 1 (MFA is enabled on root)"
            )
        else:
            evidence.append(
                "AccountSummary: AccountMFAEnabled = 0 (MFA is NOT enabled on root)"
            )
    except (ValueError, ClientError) as e:
        evidence.append(f"AccountSummary: unavailable ({e})")
        logger.warning(f"Could not check account summary for root MFA: {e}")

    # Check via Credential Report
    try:
        report = get_credential_report()
        if report:
            credential_report_available = True
            root_user = None
            for row in report:
                if row.get("user") == "<root_account>":
                    root_user = row
                    break

            if root_user:
                mfa_active = root_user.get("mfa_active", "false").lower() == "true"
                if mfa_active:
                    mfa_enabled = True
                    evidence.append(
                        "CredentialReport: root account mfa_active = true"
                    )
                else:
                    evidence.append(
                        "CredentialReport: root account mfa_active = false "
                        "(MFA is NOT enabled)"
                    )
            else:
                evidence.append(
                    "CredentialReport: <root_account> user entry not found"
                )
        else:
            evidence.append("CredentialReport: empty (possibly access denied)")
    except (ValueError, RuntimeError, ClientError) as e:
        evidence.append(f"CredentialReport: unavailable ({e})")
        logger.warning(f"Could not check credential report for root MFA: {e}")

    result: dict[str, Any] = {
        "mfa_enabled": mfa_enabled,
        "evidence": evidence,
        "account_summary_available": account_summary_available,
        "credential_report_available": credential_report_available,
    }
    logger.info(f"Root MFA check result: mfa_enabled={mfa_enabled}")
    return result
