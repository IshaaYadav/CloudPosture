"""Pytest fixtures and configuration for AWS testing with Moto."""

import os
from typing import Generator
import pytest
import boto3
from moto import mock_aws

# Ensure tests never hit real AWS and use mock credentials
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "ap-southeast-2"
os.environ["AWS_REGION"] = "ap-southeast-2"
os.environ["POSTURE_RESULTS_BUCKET"] = "test-posture-reports-bucket"
os.environ["APP_ENV"] = "testing"


@pytest.fixture(autouse=True)
def aws_credentials() -> None:
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "ap-southeast-2"


@pytest.fixture
def mocked_aws() -> Generator[None, None, None]:
    """Start moto mock_aws context covering all services."""
    with mock_aws():
        # Setup S3 bucket for reports
        s3 = boto3.client("s3", region_name="ap-southeast-2")
        s3.create_bucket(
            Bucket="test-posture-reports-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )
        yield

