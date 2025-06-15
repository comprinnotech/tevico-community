"""
Test for RDS instance backup enabled check.
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.rds.rds_instance_backup_enabled import rds_instance_backup_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestRdsInstanceBackupEnabled:
    """Test cases for RDS instance backup enabled check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="rds_instance_backup_enabled",
            CheckTitle="Ensure RDS instances have backup enabled.",
            CheckType=["data-protection"],
            ServiceName="rds",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:rds:region:account-id:db-instance",
            Severity="medium",
            ResourceType="AwsRdsDbInstance",
            Description="Ensure RDS instances have backup enabled.",
            Risk="If backup is not enabled, data is vulnerable.",
            RelatedUrl="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws rds modify-db-instance --db-instance-identifier <db_instance_id> --backup-retention-period 7 --apply-immediately",
                    Terraform="https://docs.prowler.com/checks/aws/general-policies/ensure-that-rds-instances-have-backup-policy#terraform",
                    NativeIaC=None,
                    Other="https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/RDS/rds-automated-backups-enabled.html"
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable automated backup for production data. Define a retention period and periodically test backup restoration.",
                    Url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"
                )
            ),
            Categories=["data-protection"]
        )

        self.check = rds_instance_backup_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_backup_enabled(self):
        """Test when backup is enabled for the RDS instance."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [{
                "DBInstanceIdentifier": "test-db",
                "DBInstanceArn": "arn:aws:rds:region:account:db:test-db",
                "BackupRetentionPeriod": 7
            }]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Backup is enabled with retention period of 7 days" in report.resource_ids_status[0].summary

    def test_backup_disabled(self):
        """Test when backup is disabled (retention period is 0)."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [{
                "DBInstanceIdentifier": "test-db",
                "DBInstanceArn": "arn:aws:rds:region:account:db:test-db",
                "BackupRetentionPeriod": 0
            }]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Backup is NOT enabled for RDS instance" in report.resource_ids_status[0].summary

    def test_no_rds_instances(self):
        """Test when there are no RDS instances in the account."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": []
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No RDS instances found." in report.resource_ids_status[0].summary

    def test_client_error(self):
        """Test when the client throws an error during describe call."""
        self.mock_client.describe_db_instances.side_effect = ClientError(
            error_response={"Error": {"Code": "InternalFailure", "Message": "Something went wrong"}},
            operation_name="DescribeDBInstances"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving RDS instance details." in report.resource_ids_status[0].summary
