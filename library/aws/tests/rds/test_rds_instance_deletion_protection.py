import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError, BotoCoreError

from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation
)
from library.aws.checks.rds.rds_instance_deletion_protection import rds_instance_deletion_protection


class TestRdsInstanceDeletionProtection:
    """Test cases for RDS instance deletion protection check."""

    def setup_method(self):
        """Set up test method with metadata and mocked session."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="rds_instance_deletion_protection",
            CheckTitle="RDS Instance Deletion Protection Enabled",
            CheckType=["security"],
            ServiceName="rds",
            SubServiceName="instance",
            ResourceIdTemplate="arn:aws:rds:{region}:{account_id}:db:{db_instance_identifier}",
            Severity="high",
            ResourceType="rds-instance",
            Risk="Accidental deletion of RDS instances can lead to data loss.",
            RelatedUrl="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws rds modify-db-instance --db-instance-identifier <db-name> --deletion-protection",
                    Terraform='resource "aws_db_instance" "example" {\n  deletion_protection = true\n}',
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable deletion protection on RDS instances to prevent accidental deletion.",
                    Url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"
                )
            ),
            Description="Checks if RDS instances have deletion protection enabled.",
            Categories=["security", "resilience"]
        )

        self.check = rds_instance_deletion_protection(metadata=metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_rds_instance_with_deletion_protection(self):
        """RDS instance has deletion protection enabled."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-instance-1",
                    "DBInstanceArn": "arn:aws:rds:region:account-id:db:test-instance-1",
                    "DeletionProtection": True
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Deletion protection is enabled" in report.resource_ids_status[0].summary

    def test_rds_instance_without_deletion_protection(self):
        """RDS instance has deletion protection disabled."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-instance-2",
                    "DBInstanceArn": "arn:aws:rds:region:account-id:db:test-instance-2",
                    "DeletionProtection": False
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Deletion protection is NOT enabled" in report.resource_ids_status[0].summary

    def test_no_rds_instances_present(self):
        """No RDS instances are present in the account."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": []
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No RDS instances found" in report.resource_ids_status[0].summary

    def test_missing_deletion_protection_key(self):
        """RDS instance does not have the DeletionProtection key."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-instance-3",
                    "DBInstanceArn": "arn:aws:rds:region:account-id:db:test-instance-3"
                    # DeletionProtection is missing
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Deletion protection is NOT enabled" in report.resource_ids_status[0].summary

    def test_client_error_handling(self):
        """Test when boto3 throws a ClientError."""
        error_response = {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "User is not authorized to perform this action."
            }
        }
        self.mock_client.describe_db_instances.side_effect = ClientError(error_response, "DescribeDBInstances")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving RDS instance details." in report.resource_ids_status[0].summary
