"""Pydantic v2 schemas for AWS resource representations and scan results."""

from typing import Any, Optional

from pydantic import BaseModel, Field


class AWSStatus(BaseModel):
    """Current AWS connection status."""

    account_id: str = ""
    arn: str = ""
    user_id: str = ""
    region: str = ""
    status: str = "disconnected"
    connected: bool = False
    timestamp: str = ""
    last_verified: str = ""
    error: Optional[str] = None


class EC2Instance(BaseModel):
    """Representation of an EC2 instance."""

    instance_id: str
    name: str
    instance_type: str
    region: str
    state: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_group_ids: list[str] = Field(default_factory=list)
    security_group_names: list[str] = Field(default_factory=list)


class SecurityGroupRule(BaseModel):
    """A single inbound or outbound security-group rule."""

    protocol: str
    from_port: int
    to_port: int
    cidr_ranges: list[str] = Field(default_factory=list)
    ipv6_ranges: list[str] = Field(default_factory=list)
    description: str = ""


class SecurityGroup(BaseModel):
    """AWS VPC Security Group with its rules."""

    group_id: str
    group_name: str
    description: str
    vpc_id: str
    region: str
    inbound_rules: list[SecurityGroupRule] = Field(default_factory=list)
    outbound_rules: list[SecurityGroupRule] = Field(default_factory=list)


class S3Bucket(BaseModel):
    """S3 bucket metadata and security configuration."""

    name: str
    region: str = "us-east-1"
    encryption_enabled: bool = False
    encryption_type: Optional[str] = None
    public_access_block: Optional[dict] = None
    is_public: bool = False
    versioning_enabled: bool = False
    policy_status: Optional[dict] = None
    acl_grants: list[dict] = Field(default_factory=list)


class CheckResult(BaseModel):
    """Result of a single posture check."""

    check_id: str
    check_name: str
    description: str
    severity: str
    status: str
    evidence: list[Any] = Field(default_factory=list)
    remediation: str
    timestamp: str
    category: str
    affected_resources: list[str] = Field(default_factory=list)


class PostureScore(BaseModel):
    """Aggregate posture scoring summary."""

    total_checks: int
    passed: int
    failed: int
    errors: int
    score: Optional[float] = None
    rating: str = "N/A"


class StorageVerification(BaseModel):
    """Result of verifying S3 storage access."""

    bucket_name: str
    bucket: str = ""
    write_access: bool = False
    read_access: bool = False
    delete_access: bool = False
    encryption_working: bool = False
    status: str = "FAILED"
    success: bool = False
    message: str = ""
    timestamp: str = ""
    details: dict = Field(default_factory=dict)


class ScanSummary(BaseModel):
    """High-level summary of a scan run."""

    scan_id: str
    timestamp: str
    account_id: str
    regions_scanned: list[str] = Field(default_factory=list)
    total_resources: int = 0
    total_instances: int = 0
    total_buckets: int = 0
    total_security_groups: int = 0
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    score: Optional[float] = None
    score_display: str = "N/A"
    posture_score: Optional[PostureScore] = None
    storage_status: str = "pending"


class ScanHistoryItem(BaseModel):
    """Lightweight record for listing past scans."""

    scan_id: str
    timestamp: str
    account_id: str
    score: Optional[float] = None
    score_display: str = "N/A"
    total_resources: int = 0
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    storage_key: str = ""
    s3_key: str = ""


class ScanReport(BaseModel):
    """Full scan report containing all collected data and check results."""

    scan_id: str
    timestamp: str
    account_id: str
    region: str = ""
    identity: Optional[dict] = None
    regions_scanned: list[str] = Field(default_factory=list)
    instances: list[EC2Instance] = Field(default_factory=list)
    buckets: list[S3Bucket] = Field(default_factory=list)
    security_groups: list[SecurityGroup] = Field(default_factory=list)
    check_results: list[CheckResult] = Field(default_factory=list)
    posture_score: Optional[PostureScore] = None
    summary: Optional[ScanSummary] = None
    storage_status: str = "pending"
    storage_key: Optional[str] = None
    storage: Optional[dict] = None
