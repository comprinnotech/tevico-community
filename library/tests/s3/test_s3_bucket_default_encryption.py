import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.s3.s3_bucket_default_encryption import s3_bucket_default_encryption
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, AwsResource, ResourceStatus
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


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

    def infer_report_status(self, report):
        """Infer report.status manually based on individual resource statuses."""
        statuses = [r.status for r in report.resource_ids_status]
        if CheckStatus.FAILED in statuses:
            return CheckStatus.FAILED
        elif CheckStatus.UNKNOWN in statuses:
            return CheckStatus.UNKNOWN
        elif all(s == CheckStatus.PASSED for s in statuses):
            return CheckStatus.PASSED
        return None

    def test_bucket_with_kms_encryption(self):
        """Test when S3 bucket has KMS default encryption enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "secure-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': 'alias/aws/s3'
                    }
                }]
            }
        }

        report = self.check.execute(self.mock_session)

        inferred_status = self.infer_report_status(report)
        assert inferred_status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "default encryption enabled using KMS key" in report.resource_ids_status[0].summary

    def test_bucket_with_aes256_encryption(self):
        """Test when S3 bucket has AES256 (SSE-S3) default encryption enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "basic-encrypted-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        }

        report = self.check.execute(self.mock_session)

        inferred_status = self.infer_report_status(report)
        assert inferred_status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "default encryption enabled using Amazon S3-managed keys" in report.resource_ids_status[0].summary

    def test_bucket_without_encryption(self):
        """Test when S3 bucket does not have default encryption enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [{"Name": "unencrypted-bucket"}]}
        ]
        self.mock_client.get_bucket_encryption.side_effect = ClientError(
            error_response={"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            operation_name="GetBucketEncryption"
        )

        report = self.check.execute(self.mock_session)

        inferred_status = self.infer_report_status(report)
        assert inferred_status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does not have default encryption enabled" in report.resource_ids_status[0].summary