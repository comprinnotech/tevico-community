"""
Test for S3 bucket object versioning check.
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from library.aws.checks.s3.s3_bucket_object_versioning import s3_bucket_object_versioning
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)


class TestS3BucketObjectVersioning:
    """Test cases for S3 bucket object versioning check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="s3_bucket_object_versioning",
            CheckTitle="Ensure S3 buckets have object versioning enabled",
            CheckType=["Data Protection", "Disaster Recovery"],
            ServiceName="s3",
            SubServiceName="",
            ResourceIdTemplate="arn:partition:s3:::bucket_name",
            Severity="medium",
            ResourceType="AwsS3Bucket",
            Risk="Without versioning, accidentally deleted or overwritten objects cannot be recovered.",
            RelatedUrl="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws s3api put-bucket-versioning --bucket my-bucket-name --versioning-configuration Status=Enabled",
                    Terraform='''resource "aws_s3_bucket" "example" {
  bucket = "my-bucket-name"
}
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}''',
                    NativeIaC=None,
                    Other=None,
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable versioning for S3 buckets containing important data.",
                    Url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                ),
            ),
            Description="Ensure S3 buckets have object versioning enabled to protect against accidental deletion and provide data recovery capabilities.",
            Categories=[],
        )

        self.check = s3_bucket_object_versioning(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_bucket_with_versioning_enabled(self):
        """Test when a bucket has versioning enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "versioned-bucket"}]}
        ]
        self.mock_client.get_bucket_versioning.return_value = {"Status": "Enabled"}

        report = self.check.execute(self.mock_session)

        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "has object versioning enabled" in report.resource_ids_status[0].summary

    def test_bucket_with_versioning_suspended(self):
        """Test when a bucket has versioning suspended."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "suspended-bucket"}]}
        ]
        self.mock_client.get_bucket_versioning.return_value = {"Status": "Suspended"}

        report = self.check.execute(self.mock_session)

        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "has object versioning suspended" in report.resource_ids_status[0].summary

    def test_bucket_with_no_versioning_config(self):
        """Test when a bucket has no versioning configuration."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "unversioned-bucket"}]}
        ]
        self.mock_client.get_bucket_versioning.return_value = {}

        report = self.check.execute(self.mock_session)

        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does not have object versioning enabled" in report.resource_ids_status[0].summary

    def test_no_buckets_present(self):
        """Test when no S3 buckets are present in the account."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [{"Buckets": []}]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert "No S3 buckets found" in report.resource_ids_status[0].summary