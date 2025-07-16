import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError, EndpointConnectionError

from library.aws.checks.s3.s3_bucket_default_encryption import s3_bucket_default_encryption
from tevico.engine.entities.report.check_model import (
    CheckStatus, CheckMetadata,
    Remediation, RemediationCode, RemediationRecommendation
)


class TestS3BucketDefaultEncryption:
    """Test cases for S3 bucket default encryption check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="s3_bucket_default_encryption",
            CheckTitle="Ensure S3 buckets have default encryption (SSE) enabled and use a bucket policy to enforce it.",
            CheckType=["Data Protection"],
            ServiceName="s3",
            SubServiceName="",
            ResourceIdTemplate="arn:partition:s3:::bucket_name",
            Severity="medium",
            ResourceType="AwsS3Bucket",
            Risk="Amazon S3 default encryption provides a way to set the default encryption behavior for an S3 bucket. This will ensure data-at-rest is encrypted.",
            RelatedUrl="",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws s3api put-bucket-encryption --bucket <bucket_name> --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                    Terraform="",
                    NativeIaC="",
                    Other=""
                ),
                Recommendation=RemediationRecommendation(
                    Text="Ensure that S3 buckets have encryption at rest enabled.",
                    Url="https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/"
                )
            ),
            Description="Ensure that S3 buckets have default encryption (SSE) enabled and use a bucket policy to enforce it.",
            Categories=["encryption"]
        )

        self.check = s3_bucket_default_encryption(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_kms_encryption(self):
        """Test bucket with KMS encryption enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "secure-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/aws/s3"
                    }
                }]
            }
        }

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "KMS key" in report.resource_ids_status[0].summary

    def test_aes256_encryption(self):
        """Test bucket with AES256 (SSE-S3) encryption."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "basic-encrypted-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }
        }

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Amazon S3-managed keys" in report.resource_ids_status[0].summary

    def test_no_encryption(self):
        """Test when bucket does not have default encryption enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "unencrypted-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.side_effect = ClientError(
            error_response={"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            operation_name="GetBucketEncryption"
        )

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does not have default encryption enabled" in report.resource_ids_status[0].summary

    def test_unknown_client_error(self):
        """Test for unknown ClientError."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "unknown-error-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.side_effect = ClientError(
            error_response={"Error": {"Code": "InternalError", "Message": "Something went wrong"}},
            operation_name="GetBucketEncryption"
        )

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Failed to retrieve encryption settings" in report.resource_ids_status[0].summary

    def test_boto_core_error(self):
        """Test BotoCoreError such as network failure."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "error-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.side_effect = EndpointConnectionError(endpoint_url="https://s3.amazonaws.com")

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Failed to retrieve encryption settings" in report.resource_ids_status[0].summary

    def test_no_buckets(self):
        """Test when no S3 buckets exist."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": []}
        ]

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No S3 buckets found" in report.resource_ids_status[0].summary
