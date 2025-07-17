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
    """Test cases for RDS backup enabled check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="rds_instance_backup_enabled",
            CheckTitle="Ensure RDS instances have backup enabled.",
            CheckType=[],
            ServiceName="rds",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:rds:region:account-id:db-instance",
            Severity="medium",
            ResourceType="AwsRdsDbInstance",
            Description="Ensure RDS instances have backup enabled.",
            Risk="If backup is not enabled, data is vulnerable. Human error or bad actors could erase or modify data.",
            RelatedUrl="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws rds modify-db-instance --db-instance-identifier <db_instance_id> --backup-retention-period 7 --apply-immediately",
                    Terraform="https://docs.prowler.com/checks/aws/general-policies/ensure-that-rds-instances-have-backup-policy#terraform",
                    NativeIaC="",
                    Other="https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/RDS/rds-automated-backups-enabled.html",
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable automated backup for production data. Define a retention period and periodically test backup restoration. A Disaster Recovery process should be in place to govern Data Protection approach.",
                    Url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"
                )
            ),
            Categories=[]
        )

        self.check = rds_instance_backup_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def set_mock_describe_db_instances_response(self, instances):
        """Helper to mock the describe_db_instances response."""
        self.mock_client.describe_db_instances.return_value = {"DBInstances": instances}

    def test_rds_backup_enabled(self):
        """Test when backup is enabled on all RDS instances."""
        self.set_mock_describe_db_instances_response([
            {
                "DBInstanceIdentifier": "db-1",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:db-1",
                "BackupRetentionPeriod": 7
            }
        ])

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Backup is enabled" in report.resource_ids_status[0].summary

    def test_rds_backup_not_enabled(self):
        """Test when backup is not enabled on an RDS instance."""
        self.set_mock_describe_db_instances_response([
            {
                "DBInstanceIdentifier": "db-2",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:db-2",
                "BackupRetentionPeriod": 0
            }
        ])

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "NOT enabled" in report.resource_ids_status[0].summary

    def test_rds_backup_mixed_instances(self):
        """Test with a mix of compliant and non-compliant RDS instances."""
        self.set_mock_describe_db_instances_response([
            {
                "DBInstanceIdentifier": "db-1",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:db-1",
                "BackupRetentionPeriod": 7
            },
            {
                "DBInstanceIdentifier": "db-2",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:db-2",
                "BackupRetentionPeriod": 0
            }
        ])

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        assert any("NOT enabled" in res.summary for res in report.resource_ids_status)
        assert any(res.status == CheckStatus.FAILED for res in report.resource_ids_status)

    def test_no_rds_instances(self):
        """Test when no RDS instances are found."""
        self.set_mock_describe_db_instances_response([])

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No RDS instances found" in report.resource_ids_status[0].summary

    def test_rds_client_error(self):
        """Test when describe_db_instances raises a ClientError."""
        error_response = {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}}
        self.mock_client.describe_db_instances.side_effect = ClientError(error_response, "DescribeDBInstances")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving RDS instance details" in report.resource_ids_status[0].summary
        assert "AccessDenied" in report.resource_ids_status[0].exception

    def test_rds_generic_exception(self):
        """Test when describe_db_instances raises a generic exception."""
        self.mock_client.describe_db_instances.side_effect = Exception("Unexpected error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving RDS instance details" in report.resource_ids_status[0].summary
        assert "Unexpected error" in report.resource_ids_status[0].exception
