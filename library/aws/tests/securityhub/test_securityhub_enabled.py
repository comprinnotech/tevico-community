import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.securityhub.securityhub_enabled import securityhub_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestSecurityHubEnabled:
    """Test cases for the Security Hub enabled check."""

    def setup_method(self):
        """Set up the test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="securityhub_enabled",
            CheckTitle="Ensure Security Hub is enabled in this region",
            CheckType=["Logging and Monitoring"],
            ServiceName="securityhub",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:securityhub:{region}:{account_id}:hub/{hub-id}",
            Severity="medium",
            ResourceType="AwsSecurityHub",
            Description="Checks whether AWS Security Hub is enabled in the current region.",
            Risk="Without Security Hub enabled, AWS accounts lack centralized visibility into security findings.",
            RelatedUrl="https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-enable-disable.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws securityhub enable-security-hub --enable-default-standards",
                    Terraform="",
                    NativeIaC="",
                    Other=""
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable Security Hub in each AWS region to get a centralized view of security posture.",
                    Url="https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-enable-disable.html"
                )
            ),
            Categories=[]
        )

        self.check = securityhub_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

        # Set up custom exceptions on the mock client
        class ResourceNotFoundException(Exception):
            pass

        class InvalidAccessException(Exception):
            pass

        self.mock_client.exceptions = MagicMock()
        self.mock_client.exceptions.ResourceNotFoundException = ResourceNotFoundException
        self.mock_client.exceptions.InvalidAccessException = InvalidAccessException

    def test_securityhub_enabled_pass(self):
        """Test when Security Hub is enabled."""
        self.mock_client.describe_hub.return_value = {
            'HubArn': 'arn:aws:securityhub:us-east-1:123456789012:hub/default'
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Security Hub is enabled" in report.resource_ids_status[0].summary

    def test_securityhub_not_enabled_resource_not_found(self):
        """Test when Security Hub is not enabled (ResourceNotFoundException)."""
        self.mock_client.describe_hub.side_effect = self.mock_client.exceptions.ResourceNotFoundException()

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Security Hub is not enabled" in report.resource_ids_status[0].summary

    def test_securityhub_not_enabled_invalid_access(self):
        """Test when Security Hub is not enabled (InvalidAccessException)."""
        self.mock_client.describe_hub.side_effect = self.mock_client.exceptions.InvalidAccessException()

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Security Hub is not enabled" in report.resource_ids_status[0].summary
