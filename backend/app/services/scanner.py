"""Central Scan Orchestration Service - coordinates discovery, checks, scoring, and S3 storage."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.aws import cloudtrail, ec2, iam, s3
from app.aws.session import get_session_manager
from app.checks import (
    cloudtrail as check_cloudtrail,
    ec2_exposure as check_ec2_exposure,
    public_access_block as check_pab,
    rdp_exposure as check_rdp,
    root_mfa as check_root_mfa,
    s3_encryption as check_s3_encryption,
    s3_public_access as check_s3_public,
    ssh_exposure as check_ssh,
)
from app.checks.base import CheckResult as BaseCheckResult, CheckStatus, Severity
from app.config import get_settings
from app.schemas.aws import (
    CheckResult,
    EC2Instance,
    PostureScore,
    S3Bucket,
    ScanReport,
    ScanSummary,
    SecurityGroup,
    SecurityGroupRule,
)
from app.services.posture_score import calculate_posture_score
from app.services.report_storage import get_report_storage
from app.services.scan_state import get_scan_state

logger = logging.getLogger(__name__)


def _to_schema_check_result(res: BaseCheckResult) -> CheckResult:
    """Convert a base CheckResult dataclass to the Pydantic CheckResult schema."""
    return CheckResult(
        check_id=res.check_id,
        check_name=res.check_name,
        description=res.description,
        severity=res.severity,
        status=res.status,
        evidence=res.evidence,
        remediation=res.remediation,
        timestamp=res.timestamp,
        category=res.category,
        affected_resources=res.affected_resources,
    )


def _to_schema_instance(raw: dict[str, Any]) -> EC2Instance:
    """Safely convert a raw discovered EC2 instance dict to EC2Instance schema."""
    return EC2Instance(
        instance_id=raw.get("instance_id", "unknown"),
        name=raw.get("name", ""),
        instance_type=raw.get("instance_type", "unknown"),
        region=raw.get("region", "unknown"),
        state=raw.get("state", "unknown"),
        public_ip=raw.get("public_ip"),
        private_ip=raw.get("private_ip"),
        vpc_id=raw.get("vpc_id"),
        subnet_id=raw.get("subnet_id"),
        security_group_ids=raw.get("security_group_ids", []),
        security_group_names=raw.get("security_group_names", []),
    )


def _to_schema_bucket(raw: dict[str, Any]) -> S3Bucket:
    """Safely convert a raw discovered S3 bucket dict to S3Bucket schema."""
    return S3Bucket(
        name=raw.get("name", "unknown"),
        region=raw.get("region", "us-east-1"),
        encryption_enabled=raw.get("encryption_enabled", False),
        encryption_type=raw.get("encryption_type"),
        public_access_block=raw.get("public_access_block"),
        is_public=raw.get("is_public", False),
        versioning_enabled=raw.get("versioning_enabled", False),
        policy_status=raw.get("policy_status"),
        acl_grants=raw.get("acl_grants", []),
    )


def _to_schema_security_group(raw: dict[str, Any]) -> SecurityGroup:
    """Safely convert a raw discovered security group dict to SecurityGroup schema."""
    inbound: list[SecurityGroupRule] = []
    for r in raw.get("inbound_rules", []):
        inbound.append(
            SecurityGroupRule(
                protocol=str(r.get("protocol", "")),
                from_port=int(r.get("from_port", 0)),
                to_port=int(r.get("to_port", 0)),
                cidr_ranges=r.get("cidr_ranges", []),
                ipv6_ranges=r.get("ipv6_ranges", []),
                description=str(r.get("description", "")),
            )
        )

    outbound: list[SecurityGroupRule] = []
    for r in raw.get("outbound_rules", []):
        outbound.append(
            SecurityGroupRule(
                protocol=str(r.get("protocol", "")),
                from_port=int(r.get("from_port", 0)),
                to_port=int(r.get("to_port", 0)),
                cidr_ranges=r.get("cidr_ranges", []),
                ipv6_ranges=r.get("ipv6_ranges", []),
                description=str(r.get("description", "")),
            )
        )

    return SecurityGroup(
        group_id=raw.get("group_id", "unknown"),
        group_name=raw.get("group_name", "unknown"),
        description=raw.get("description", ""),
        vpc_id=raw.get("vpc_id", ""),
        region=raw.get("region", "unknown"),
        inbound_rules=inbound,
        outbound_rules=outbound,
    )


class ScanOrchestrator:
    """Coordinates cloud resource discovery, evaluates CIS checks, computes posture score,
    and saves the full audit report to S3."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.session_manager = get_session_manager()
        self.storage = get_report_storage()
        self.state = get_scan_state()

    def run_full_scan(self) -> ScanReport:
        """Run an end-to-end cloud posture security scan.

        Sequence:
            1. Verify AWS Identity (STS)
            2. Discover enabled AWS regions
            3. Discover EC2 instances and Security Groups
            4. Discover S3 buckets and security configurations
            5. Fetch IAM and CloudTrail state for identity/logging checks
            6. Execute all 8 CIS-inspired security checks
            7. Calculate posture score
            8. Assemble ScanReport and serialize to JSON
            9. Upload scan report to S3 with SSE-S3 encryption
            10. Update in-memory scan state
            11. Return ScanReport
        """
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        logger.info(f"Starting full security posture scan: ID={scan_id}")

        # 1. AWS Identity
        identity = self.session_manager.verify_identity()
        account_id = identity.get("account_id") or "UNKNOWN_ACCOUNT"
        current_region = self.settings.AWS_REGION

        # 2. Discover Regions
        regions_scanned: list[str] = [current_region]
        try:
            enabled_regions = ec2.get_enabled_regions()
            if enabled_regions:
                # Include configured region plus other enabled regions (or limit to primary regions if desired)
                # To be cost and performance conscious, prioritize current region and enabled regions
                regions_scanned = enabled_regions
        except Exception as e:
            logger.warning(f"Could not discover enabled regions, defaulting to {current_region}: {e}")

        # 3. Discover EC2 Instances & Security Groups
        raw_instances: list[dict[str, Any]] = []
        raw_security_groups: list[dict[str, Any]] = []
        try:
            logger.info("Discovering EC2 instances across regions...")
            raw_instances = ec2.discover_instances(regions_scanned)
        except Exception as e:
            logger.error(f"Error during EC2 instance discovery: {e}")

        try:
            logger.info("Discovering EC2 security groups across regions...")
            raw_security_groups = ec2.discover_security_groups(regions_scanned)
        except Exception as e:
            logger.error(f"Error during Security Group discovery: {e}")

        # 4. Discover S3 Buckets
        raw_buckets: list[dict[str, Any]] = []
        try:
            logger.info("Discovering S3 buckets and security settings...")
            raw_buckets = s3.discover_buckets()
        except Exception as e:
            logger.error(f"Error during S3 bucket discovery: {e}")

        # 5. Fetch IAM Root MFA & CloudTrail Trails
        raw_root_mfa: dict[str, Any] = {}
        try:
            logger.info("Checking IAM Root MFA...")
            raw_root_mfa = iam.check_root_mfa()
        except Exception as e:
            logger.warning(f"Error checking root MFA: {e}")
            raw_root_mfa = {
                "mfa_enabled": None,
                "evidence": [f"Error querying IAM: {str(e)}"],
                "account_summary_available": False,
                "credential_report_available": False,
            }

        raw_trails: list[dict[str, Any]] = []
        try:
            logger.info("Discovering CloudTrail trails...")
            raw_trails = cloudtrail.get_trails()
        except Exception as e:
            logger.warning(f"Error querying CloudTrail: {e}")
            raw_trails = []

        # 6. Execute all 8 CIS-inspired security checks
        logger.info("Executing 8 CIS-inspired security checks...")
        check_results: list[CheckResult] = []

        # Check 1: S3 Public Access
        try:
            c1 = check_s3_public.run_check(raw_buckets)
            check_results.append(_to_schema_check_result(c1))
        except Exception as e:
            logger.error(f"Error in Check 1 (S3 Public Access): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-S3-001",
                    check_name="S3 Bucket Public Access",
                    description="Ensure no S3 buckets allow public access",
                    severity=Severity.HIGH.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Enable S3 Block Public Access on all buckets.",
                    timestamp=timestamp,
                    category="Storage",
                    affected_resources=[],
                )
            )

        # Check 2: S3 Default Encryption
        try:
            c2 = check_s3_encryption.run_check(raw_buckets)
            check_results.append(_to_schema_check_result(c2))
        except Exception as e:
            logger.error(f"Error in Check 2 (S3 Default Encryption): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-S3-002",
                    check_name="S3 Default Encryption",
                    description="Ensure all S3 buckets have default encryption enabled",
                    severity=Severity.HIGH.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Enable default SSE-S3 or SSE-KMS encryption on all buckets.",
                    timestamp=timestamp,
                    category="Storage",
                    affected_resources=[],
                )
            )

        # Check 3: Root Account MFA
        try:
            c3 = check_root_mfa.run_check(raw_root_mfa)
            check_results.append(_to_schema_check_result(c3))
        except Exception as e:
            logger.error(f"Error in Check 3 (Root Account MFA): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-IAM-001",
                    check_name="Root Account MFA",
                    description="Ensure MFA is enabled for the root AWS account",
                    severity=Severity.CRITICAL.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Enable virtual or hardware MFA on the root AWS account.",
                    timestamp=timestamp,
                    category="Identity",
                    affected_resources=[],
                )
            )

        # Check 4: CloudTrail Multi-Region Logging
        try:
            c4 = check_cloudtrail.run_check(raw_trails)
            check_results.append(_to_schema_check_result(c4))
        except Exception as e:
            logger.error(f"Error in Check 4 (CloudTrail Logging): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-LOG-001",
                    check_name="CloudTrail Multi-Region Logging",
                    description="Ensure CloudTrail is enabled in all regions with multi-region logging",
                    severity=Severity.HIGH.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Create a multi-region CloudTrail trail logging to S3.",
                    timestamp=timestamp,
                    category="Logging",
                    affected_resources=[],
                )
            )

        # Check 5: SSH Public Exposure
        try:
            c5 = check_ssh.run_check(raw_security_groups)
            check_results.append(_to_schema_check_result(c5))
        except Exception as e:
            logger.error(f"Error in Check 5 (SSH Exposure): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-NET-001",
                    check_name="SSH Public Exposure",
                    description="Ensure no security groups allow unrestricted SSH access from internet",
                    severity=Severity.HIGH.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Restrict SSH port 22 access to specific trusted IPs.",
                    timestamp=timestamp,
                    category="Network",
                    affected_resources=[],
                )
            )

        # Check 6: RDP Public Exposure
        try:
            c6 = check_rdp.run_check(raw_security_groups)
            check_results.append(_to_schema_check_result(c6))
        except Exception as e:
            logger.error(f"Error in Check 6 (RDP Exposure): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-NET-002",
                    check_name="RDP Public Exposure",
                    description="Ensure no security groups allow unrestricted RDP access from internet",
                    severity=Severity.HIGH.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Restrict RDP port 3389 access to specific trusted IPs.",
                    timestamp=timestamp,
                    category="Network",
                    affected_resources=[],
                )
            )

        # Check 7: S3 Public Access Block Configuration
        try:
            c7 = check_pab.run_check(raw_buckets)
            check_results.append(_to_schema_check_result(c7))
        except Exception as e:
            logger.error(f"Error in Check 7 (S3 Public Access Block): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-S3-003",
                    check_name="S3 Public Access Block Configuration",
                    description="Ensure all S3 buckets have all four Public Access Block settings enabled",
                    severity=Severity.MEDIUM.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Enable all four S3 Public Access Block settings on each bucket.",
                    timestamp=timestamp,
                    category="Storage",
                    affected_resources=[],
                )
            )

        # Check 8: EC2 Public Instance Exposure
        try:
            c8 = check_ec2_exposure.run_check(raw_instances, raw_security_groups)
            check_results.append(_to_schema_check_result(c8))
        except Exception as e:
            logger.error(f"Error in Check 8 (EC2 Public Exposure): {e}")
            check_results.append(
                CheckResult(
                    check_id="CIS-EC2-001",
                    check_name="EC2 Public Instance Exposure",
                    description="Ensure no running EC2 instances with public IPs have exposed management ports",
                    severity=Severity.MEDIUM.value,
                    status=CheckStatus.ERROR.value,
                    evidence=[{"error": str(e)}],
                    remediation="Remove public IP or restrict security group management rules.",
                    timestamp=timestamp,
                    category="Compute",
                    affected_resources=[],
                )
            )

        # 7. Posture Score
        posture_score = calculate_posture_score(check_results)

        # Convert resources to schemas
        schema_instances = [_to_schema_instance(i) for i in raw_instances]
        schema_buckets = [_to_schema_bucket(b) for b in raw_buckets]
        schema_security_groups = [_to_schema_security_group(sg) for sg in raw_security_groups]

        total_resources = len(schema_instances) + len(schema_buckets)

        summary = ScanSummary(
            scan_id=scan_id,
            timestamp=timestamp,
            account_id=account_id,
            regions_scanned=regions_scanned,
            total_resources=total_resources,
            total_instances=len(schema_instances),
            total_buckets=len(schema_buckets),
            total_security_groups=len(schema_security_groups),
            total_checks=len(check_results),
            passed=posture_score.passed,
            failed=posture_score.failed,
            errors=posture_score.errors,
            score=posture_score.score,
            score_display=f"{posture_score.score}%" if posture_score.score is not None else "N/A",
            posture_score=posture_score,
            storage_status="pending",
        )

        storage_status = "pending"
        storage_key = None
        storage_dict = {
            "status": "pending",
            "bucket": self.storage.bucket_name,
            "key": "",
        }

        # 8 & 9. Upload to S3
        report_dict: dict[str, Any] = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "account_id": account_id,
            "region": current_region,
            "identity": identity,
            "regions_scanned": regions_scanned,
            "instances": [inst.model_dump() for inst in schema_instances],
            "buckets": [b.model_dump() for b in schema_buckets],
            "security_groups": [sg.model_dump() for sg in schema_security_groups],
            "check_results": [cr.model_dump() for cr in check_results],
            "posture_score": posture_score.model_dump(),
            "summary": summary.model_dump(),
            "storage_status": "pending",
            "storage_key": None,
        }

        try:
            logger.info("Uploading scan report to S3...")
            storage_key = self.storage.upload_scan_report(report_dict)
            storage_status = "stored"
            storage_dict = {
                "status": "stored",
                "bucket": self.storage.bucket_name,
                "key": storage_key,
            }
            summary.storage_status = "stored"
            logger.info(f"Scan report successfully stored at S3 key: {storage_key}")
        except Exception as e:
            logger.error(f"S3 report upload failed: {e}")
            storage_status = "storage-failed"
            storage_dict = {
                "status": "storage-failed",
                "bucket": self.storage.bucket_name,
                "key": "",
                "error": str(e),
            }
            summary.storage_status = "storage-failed"

        # Final ScanReport model
        scan_report = ScanReport(
            scan_id=scan_id,
            timestamp=timestamp,
            account_id=account_id,
            region=current_region,
            identity=identity,
            regions_scanned=regions_scanned,
            instances=schema_instances,
            buckets=schema_buckets,
            security_groups=schema_security_groups,
            check_results=check_results,
            posture_score=posture_score,
            summary=summary,
            storage_status=storage_status,
            storage_key=storage_key,
            storage=storage_dict,
        )

        # 10. Update in-memory state
        self.state.update(scan_report)

        return scan_report


# Singleton scanner instance
_scanner: Optional[ScanOrchestrator] = None


def get_scanner() -> ScanOrchestrator:
    """Return the singleton ScanOrchestrator instance."""
    global _scanner
    if _scanner is None:
        _scanner = ScanOrchestrator()
    return _scanner

