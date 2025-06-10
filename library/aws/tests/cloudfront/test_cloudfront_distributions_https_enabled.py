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
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {"Items": []}
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert (
            "No CloudFront distributions found."
            in report.resource_ids_status[0].summary
        )

    def test_https_only_enabled(self):
        """Test when all distributions require HTTPS."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-1",
                        "DomainName": "d1.cloudfront.net",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-1",
                    }
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"}
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert (
            "CloudFront distribution 'dist-1' does NOT enforce HTTPS (policy: allow-all)."
            == report.resource_ids_status[0].summary
        )

    def test_https_not_enforced(self):
        """Test when a distribution allows HTTP."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-2",
                        "DomainName": "d2.cloudfront.net",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-2",
                    }
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"}
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert (
            "CloudFront distribution 'dist-2' does NOT enforce HTTPS (policy: allow-all)."
            == report.resource_ids_status[0].summary
        )

    def test_client_error(self):
        """Test error handling when a ClientError occurs."""
        self.mock_cf.list_distributions.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListDistributions"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert (
            "Error retrieving CloudFront distributions."
            in report.resource_ids_status[0].summary
        )

    def test_https_policy_check(self):
        """Test the enforcement of HTTPS policy on CloudFront distributions."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "dist-3",
                        "DomainName": "d3.cloudfront.net",
                        "ARN": "arn:aws:cloudfront::account:distribution/dist-3",
                    }
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-list"}
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert (
            "CloudFront distribution 'dist-3' does NOT enforce HTTPS (policy: allow-all)."
            == report.resource_ids_status[0].summary
        )
        assert (
            len(report.resource_ids_status) == 1
        )  # Ensure no duplicate entries are added
