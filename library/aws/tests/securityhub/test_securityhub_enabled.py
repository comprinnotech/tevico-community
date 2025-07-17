import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.securityhub.securityhub_enabled import securityhub_enabled
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)


class TestSecurityHubEnabled:
    """Test cases for the Security Hub enabled check."""

    def setup_method(self):
        """Set up mock AWS session and Security Hub client."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="securityhub_enabled",
            CheckTitle="Ensure Security Hub is enabled and has standard subscriptions.",
            CheckType=["Logging and Monitoring"],
            ServiceName="securityhub",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:securityhub:{region}:{account_id}:hub/{hub-id}",
            Severity="medium",
            ResourceType="Other",
            Description="Check if Security Hub is enabled and has standard subscriptions.",
            Risk="AWS Security Hub gives you a comprehensive view of your security alerts and security posture across your AWS accounts.",
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

        # Create custom exceptions similar to Boto3
        class ResourceNotFoundException(Exception):
            pass

        class InvalidAccessException(Exception):
            pass

        self.mock_client.exceptions = MagicMock()
        self.mock_client.exceptions.ResourceNotFoundException = ResourceNotFoundException
        self.mock_client.exceptions.InvalidAccessException = InvalidAccessException

    def test_securityhub_enabled(self):
        """Should pass when Security Hub is enabled and returns a valid HubArn."""
        self.mock_client.describe_hub.return_value = {
            'HubArn': 'arn:aws:securityhub:us-east-1:123456789012:hub/default'
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "enabled" in report.resource_ids_status[0].summary.lower()

    def test_securityhub_enabled_missing_arn(self):
        """Should return UNKNOWN when describe_hub returns no HubArn."""
        self.mock_client.describe_hub.return_value = {}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving" in report.resource_ids_status[0].summary or "HubArn" not in report.resource_ids_status[0].summary

    def test_securityhub_resource_not_found(self):
        """Should fail when Security Hub is not enabled (ResourceNotFoundException)."""
        self.mock_client.describe_hub.side_effect = self.mock_client.exceptions.ResourceNotFoundException()

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "not enabled" in report.resource_ids_status[0].summary.lower()

    def test_securityhub_invalid_access(self):
        """Should fail when Security Hub access is denied (InvalidAccessException)."""
        self.mock_client.describe_hub.side_effect = self.mock_client.exceptions.InvalidAccessException()

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "not enabled" in report.resource_ids_status[0].summary.lower()

    def test_securityhub_client_error(self):
        """Should return UNKNOWN when a generic ClientError (e.g. access denied) occurs."""
        self.mock_client.describe_hub.side_effect = ClientError(
            error_response={'Error': {'Code': 'AccessDeniedException', 'Message': 'Access denied'}},
            operation_name='DescribeHub'
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "access denied" in report.resource_ids_status[0].summary.lower()
        assert "Access denied" in report.resource_ids_status[0].summary
