"""Tests for all 8 CIS-inspired security checks."""

import pytest
from app.checks.base import CheckStatus
from app.checks import (
    cloudtrail as check_cloudtrail,
    ec2_exposure as check_ec2,
    public_access_block as check_pab,
    rdp_exposure as check_rdp,
    root_mfa as check_root_mfa,
    s3_encryption as check_s3_enc,
    s3_public_access as check_s3_pub,
    ssh_exposure as check_ssh,
)


# Check 1: S3 Public Access
def test_check_s3_public_access_pass() -> None:
    buckets = [{"name": "private-bucket", "is_public": False, "policy_status": {"IsPublic": False}}]
    res = check_s3_pub.run_check(buckets)
    assert res.status == CheckStatus.PASS.value


def test_check_s3_public_access_fail() -> None:
    buckets = [
        {"name": "public-bucket", "is_public": True, "policy_status": {"IsPublic": True}}
    ]
    res = check_s3_pub.run_check(buckets)
    assert res.status == CheckStatus.FAIL.value
    assert "public-bucket" in res.affected_resources


def test_check_s3_public_access_error_empty() -> None:
    res = check_s3_pub.run_check([])
    assert res.status == CheckStatus.ERROR.value


# Check 2: S3 Default Encryption
def test_check_s3_encryption_pass() -> None:
    buckets = [{"name": "enc-bucket", "encryption_enabled": True, "encryption_type": "AES256"}]
    res = check_s3_enc.run_check(buckets)
    assert res.status == CheckStatus.PASS.value


def test_check_s3_encryption_fail() -> None:
    buckets = [{"name": "plain-bucket", "encryption_enabled": False, "encryption_type": None}]
    res = check_s3_enc.run_check(buckets)
    assert res.status == CheckStatus.FAIL.value
    assert "plain-bucket" in res.affected_resources


# Check 3: Root MFA
def test_check_root_mfa_pass() -> None:
    info = {"mfa_enabled": True, "evidence": ["MFA Active"], "account_summary_available": True}
    res = check_root_mfa.run_check(info)
    assert res.status == CheckStatus.PASS.value


def test_check_root_mfa_fail() -> None:
    info = {"mfa_enabled": False, "evidence": ["MFA Not Active"], "account_summary_available": True}
    res = check_root_mfa.run_check(info)
    assert res.status == CheckStatus.FAIL.value


def test_check_root_mfa_error_unavailable() -> None:
    info = {"mfa_enabled": None, "evidence": ["Access Denied"], "account_summary_available": False, "credential_report_available": False}
    res = check_root_mfa.run_check(info)
    assert res.status == CheckStatus.ERROR.value


# Check 4: CloudTrail Multi-Region Logging
def test_check_cloudtrail_pass() -> None:
    trails = [{"trail_name": "main-trail", "is_multi_region": True, "is_logging": True}]
    res = check_cloudtrail.run_check(trails)
    assert res.status == CheckStatus.PASS.value


def test_check_cloudtrail_fail() -> None:
    trails = [{"trail_name": "inactive-trail", "is_multi_region": True, "is_logging": False}]
    res = check_cloudtrail.run_check(trails)
    assert res.status == CheckStatus.FAIL.value


def test_check_cloudtrail_error_none() -> None:
    res = check_cloudtrail.run_check(None)
    assert res.status == CheckStatus.ERROR.value


# Check 5: SSH Public Exposure
def test_check_ssh_exposure_pass() -> None:
    sgs = [
        {
            "group_id": "sg-123",
            "group_name": "internal-ssh",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": ["10.0.0.0/8"], "ipv6_ranges": []}
            ],
        }
    ]
    res = check_ssh.run_check(sgs)
    assert res.status == CheckStatus.PASS.value


def test_check_ssh_exposure_fail() -> None:
    sgs = [
        {
            "group_id": "sg-bad",
            "group_name": "public-ssh",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": ["0.0.0.0/0"], "ipv6_ranges": []}
            ],
        }
    ]
    res = check_ssh.run_check(sgs)
    assert res.status == CheckStatus.FAIL.value
    assert "sg-bad" in res.affected_resources


# Check 6: RDP Public Exposure
def test_check_rdp_exposure_pass() -> None:
    sgs = [
        {
            "group_id": "sg-456",
            "group_name": "internal-rdp",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ranges": ["192.168.1.0/24"], "ipv6_ranges": []}
            ],
        }
    ]
    res = check_rdp.run_check(sgs)
    assert res.status == CheckStatus.PASS.value


def test_check_rdp_exposure_fail() -> None:
    sgs = [
        {
            "group_id": "sg-bad-rdp",
            "group_name": "public-rdp",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ranges": ["::/0"], "ipv6_ranges": ["::/0"]}
            ],
        }
    ]
    res = check_rdp.run_check(sgs)
    assert res.status == CheckStatus.FAIL.value
    assert "sg-bad-rdp" in res.affected_resources


# Check 7: S3 Public Access Block Configuration
def test_check_pab_pass() -> None:
    buckets = [
        {
            "name": "secure-bucket",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        }
    ]
    res = check_pab.run_check(buckets)
    assert res.status == CheckStatus.PASS.value


def test_check_pab_fail() -> None:
    buckets = [
        {
            "name": "insecure-bucket",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        }
    ]
    res = check_pab.run_check(buckets)
    assert res.status == CheckStatus.FAIL.value
    assert "insecure-bucket" in res.affected_resources


# Check 8: EC2 Public Instance Exposure
def test_check_ec2_exposure_pass_no_public_ip() -> None:
    instances = [
        {"instance_id": "i-111", "state": "running", "public_ip": None, "security_group_ids": ["sg-1"]}
    ]
    sgs = [{"group_id": "sg-1", "inbound_rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": ["0.0.0.0/0"]}]}]
    res = check_ec2.run_check(instances, sgs)
    assert res.status == CheckStatus.PASS.value


def test_check_ec2_exposure_fail_public_ip_and_exposed_port() -> None:
    instances = [
        {"instance_id": "i-bad", "state": "running", "public_ip": "54.1.2.3", "security_group_ids": ["sg-open"]}
    ]
    sgs = [
        {
            "group_id": "sg-open",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": ["0.0.0.0/0"], "ipv6_ranges": []}
            ],
        }
    ]
    res = check_ec2.run_check(instances, sgs)
    assert res.status == CheckStatus.FAIL.value
    assert "i-bad" in res.affected_resources

