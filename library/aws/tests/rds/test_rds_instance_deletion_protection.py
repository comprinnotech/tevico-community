import pytest
from unittest.mock import MagicMock
from tevico.engine.entities.report.check_model import CheckStatus
from library.aws.checks.rds.rds_instance_deletion_protection import rds_instance_deletion_protection


class TestRdsInstanceDeletionProtection:
    def setup_method(self):
        metadata = {
            "CheckID": "rds_instance_deletion_protection",
            "Provider": "aws",
            "ServiceName": "rds"
        }
        self.check = rds_instance_deletion_protection(metadata=metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_rds_instance_with_deletion_protection(self):
        """Test case where RDS instance has deletion protection enabled."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-instance-1",
                    "DBInstanceArn": "arn:aws:rds:region:account-id:db:test-instance-1",
                    "DeletionProtection": True,
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Deletion protection is enabled" in report.resource_ids_status[0].summary

    def test_rds_instance_without_deletion_protection(self):
        """Test case where RDS instance has deletion protection disabled."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-instance-2",
                    "DBInstanceArn": "arn:aws:rds:region:account-id:db:test-instance-2",
                    "DeletionProtection": False,
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Deletion protection is NOT enabled" in report.resource_ids_status[0].summary

    def test_no_rds_instances_present(self):
        """Test case where there are no RDS instances in the account."""
        self.mock_client.describe_db_instances.return_value = {
            "DBInstances": []
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No RDS instances found" in report.resource_ids_status[0].summary
