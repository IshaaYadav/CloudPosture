"""Tests for S3 bucket discovery and security configuration analysis."""

import boto3
import pytest
from app.aws.s3 import discover_buckets


def test_discover_buckets_empty(mocked_aws) -> None:
    """Test discovering buckets when only the report bucket exists."""
    buckets = discover_buckets()
    assert isinstance(buckets, list)
    assert len(buckets) >= 1
    assert any(b["name"] == "test-posture-reports-bucket" for b in buckets)


def test_discover_bucket_with_encryption(mocked_aws) -> None:
    """Test discovering bucket encryption configuration."""
    s3 = boto3.client("s3", region_name="ap-southeast-2")
    bucket_name = "encrypted-test-bucket"
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        },
    )

    buckets = discover_buckets()
    found = [b for b in buckets if b["name"] == bucket_name]
    assert len(found) == 1
    assert found[0]["encryption_enabled"] is True
    assert found[0]["encryption_type"] == "AES256"


def test_discover_bucket_public_access_block(mocked_aws) -> None:
    """Test discovering Public Access Block configuration."""
    s3 = boto3.client("s3", region_name="ap-southeast-2")
    bucket_name = "pab-test-bucket"
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    buckets = discover_buckets()
    found = [b for b in buckets if b["name"] == bucket_name]
    assert len(found) == 1
    pab = found[0]["public_access_block"]
    assert pab is not None
    assert pab.get("BlockPublicAcls") is True
    assert pab.get("RestrictPublicBuckets") is True

