"""Tests for AWS Session Manager and STS Identity verification."""

import pytest
from app.aws.session import AWSSessionManager, get_session_manager


def test_aws_session_creation(mocked_aws) -> None:
    """Test boto3 session and client creation."""
    manager = AWSSessionManager()
    session = manager.get_session()
    assert session is not None

    sts = manager.get_client("sts")
    assert sts is not None


def test_sts_verify_identity(mocked_aws) -> None:
    """Test identity verification via STS GetCallerIdentity."""
    manager = AWSSessionManager()
    identity = manager.verify_identity()

    assert identity["status"] == "connected"
    assert identity["account_id"] != ""
    assert "arn:aws" in identity["arn"]
    assert identity["region"] == "ap-southeast-2"


def test_singleton_session_manager() -> None:
    """Test get_session_manager returns consistent singleton."""
    m1 = get_session_manager()
    m2 = get_session_manager()
    assert m1 is m2

