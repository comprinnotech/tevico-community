import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.cloudfront.cloudfront_access_logging_enabled import (
    cloudfront_access_logging_enabled,
)


class TestCloudFrontAccessLoggingEnabled:
    """Test cases for CloudFront Access Logging Enabled check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="cloudfront_access_logging_enabled",
            CheckTitle="CloudFront distributions have access logging enabled",
            CheckType=["Security"],
            ServiceName="CloudFront",
            SubServiceName="Distribution",
            ResourceIdTemplate="arn:aws:cloudfront::{account_id}:distribution/{distribution_id}",
            Severity="medium",
            ResourceType="AWS::CloudFront::Distribution",
            Risk="Distributions without access logging may lack audit trails.",
            Description="Checks if CloudFront distributions have access logging enabled.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Enable access logging for CloudFront distributions.",
                    Url="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
                ),
            ),
        )
        self.check = cloudfront_access_logging_enabled(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_cf = MagicMock()
        self.mock_session.client.return_value = self.mock_cf

    def test_no_distributions(self):
        """Test when there are no CloudFront distributions."""
        self.mock_cf.list_distributions.return_value = {"DistributionList": {"Items": []}}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert "No distributions found." in report.resource_ids_status[0].summary

    def test_access_logging_enabled(self):
        """Test when all distributions have access logging enabled."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {"Id": "dist-1", "DomainName": "d1.cloudfront.net", "ARN": "arn:aws:cloudfront::account:distribution/dist-1"}
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "Logging": {"Enabled": True}
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert "Access Logging is ENABLED for dist-1." == report.resource_ids_status[0].summary

    def test_access_logging_disabled(self):
        """Test when a distribution does not have access logging enabled."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {"Id": "dist-2", "DomainName": "d2.cloudfront.net", "ARN": "arn:aws:cloudfront::account:distribution/dist-2"}
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "Logging": {"Enabled": False}
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "Access Logging is DISABLED for dist-2." == report.resource_ids_status[0].summary

    def test_access_logging_via_realtime_log_config(self):
        """Test when legacy logging is disabled but RealtimeLogConfigArn is set."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [{"Id": "dist-3", "ARN": "arn:aws:cloudfront::account:distribution/dist-3"}]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "Logging": {"Enabled": False},
                "DefaultCacheBehavior": {
                    "RealtimeLogConfigArn": "arn:aws:logs::123456789012:log-group/sample"
                }
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert "Access Logging is ENABLED for dist-3." == report.resource_ids_status[0].summary

    def test_get_distribution_config_raises_exception(self):
        """Test handling of general exception per distribution."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [{"Id": "dist-4", "ARN": "arn:aws:cloudfront::account:distribution/dist-4"}]
            }
        }
        self.mock_cf.get_distribution_config.side_effect = Exception("Fetch failed")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving config for dist-4." in report.resource_ids_status[0].summary

    def test_get_distribution_config_client_error(self):
        """Test handling of ClientError during config fetch."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [{"Id": "dist-5", "ARN": "arn:aws:cloudfront::account:distribution/dist-5"}]
            }
        }
        self.mock_cf.get_distribution_config.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "GetDistributionConfig"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving config for dist-5." in report.resource_ids_status[0].summary

    def test_mixed_logging_status(self):
        """Test multiple distributions with mixed logging statuses."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {"Id": "dist-1", "ARN": "arn:aws:cloudfront::account:distribution/dist-1"},
                    {"Id": "dist-2", "ARN": "arn:aws:cloudfront::account:distribution/dist-2"}
                ]
            }
        }

        def side_effect_get_config(**kwargs):
            if kwargs.get("Id") == "dist-1":
                return {"DistributionConfig": {"Logging": {"Enabled": True}}}
            else:
                return {"DistributionConfig": {"Logging": {"Enabled": False}}}

        self.mock_cf.get_distribution_config.side_effect = side_effect_get_config

        report = self.check.execute(self.mock_session)

        statuses = [r.status for r in report.resource_ids_status]
        assert CheckStatus.FAILED in statuses
        assert CheckStatus.PASSED in statuses
        assert report.status == CheckStatus.FAILED
