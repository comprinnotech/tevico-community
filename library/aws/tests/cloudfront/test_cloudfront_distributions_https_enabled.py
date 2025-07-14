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
from library.aws.checks.cloudfront.cloudfront_distributions_https_enabled import (
    cloudfront_distributions_https_enabled,
)


class TestCloudFrontDistributionsHTTPSEnabled:
    """Test cases for CloudFront Distributions HTTPS Enabled check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="cloudfront_distributions_https_enabled",
            CheckTitle="CloudFront distributions require HTTPS",
            CheckType=["Security"],
            ServiceName="CloudFront",
            SubServiceName="Distribution",
            ResourceIdTemplate="arn:aws:cloudfront::{account_id}:distribution/{distribution_id}",
            Severity="high",
            ResourceType="AWS::CloudFront::Distribution",
            Risk="Distributions allowing HTTP may expose data in transit.",
            Description="Checks if CloudFront distributions require HTTPS.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Require HTTPS for all CloudFront distributions.",
                    Url="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html",
                ),
            ),
        )
        self.check = cloudfront_distributions_https_enabled(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_cf = MagicMock()
        self.mock_session.client.return_value = self.mock_cf

    def test_no_distributions(self):
        """Test when there are no CloudFront distributions."""
        self.mock_cf.list_distributions.return_value = {"DistributionList": {"Items": []}}
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No CloudFront distributions found." in report.resource_ids_status[0].summary

    def test_https_only_enforced(self):
        """Test when HTTPS is enforced via https-only."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-1",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-1",
                        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"},
                    }
                ]
            }
        }
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "enforces HTTPS (https-only)" in report.resource_ids_status[0].summary

    def test_https_redirect_enforced(self):
        """Test when HTTPS is enforced via redirect-to-https."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-2",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-2",
                        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"},
                    }
                ]
            }
        }
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "enforces HTTPS (redirect-to-https)" in report.resource_ids_status[0].summary

    def test_https_not_enforced(self):
        """Test when HTTPS is not enforced (allow-all)."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-3",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-3",
                        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"},
                    }
                ]
            }
        }
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED  # Report status not downgraded for failed resources
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does NOT enforce HTTPS (policy: allow-all)" in report.resource_ids_status[0].summary

    def test_missing_policy_defaults_to_allow_all(self):
        """Test when ViewerProtocolPolicy is missing (defaults to allow-all)."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-4",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-4",
                        "DefaultCacheBehavior": {},  # Missing ViewerProtocolPolicy
                    }
                ]
            }
        }
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does NOT enforce HTTPS (policy: allow-all)" in report.resource_ids_status[0].summary

    def test_client_error_handling(self):
        """Test when CloudFront throws a ClientError."""
        self.mock_cf.list_distributions.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListDistributions"
        )
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving CloudFront distributions." in report.resource_ids_status[0].summary
