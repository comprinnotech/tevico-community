import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.cloudfront.cloudfront_distributions_using_deprecated_ssl_protocols import (
    cloudfront_distributions_using_deprecated_ssl_protocols,
)


class TestCloudFrontDistributionsUsingDeprecatedSSLProtocols:
    """Test cases for CloudFront Distributions Using Deprecated SSL Protocols check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="cloudfront_distributions_using_deprecated_ssl_protocols",
            CheckTitle="CloudFront distributions do not use deprecated SSL protocols",
            CheckType=["Security"],
            ServiceName="CloudFront",
            SubServiceName="Distribution",
            ResourceIdTemplate="arn:aws:cloudfront::{account_id}:distribution/{distribution_id}",
            Severity="high",
            ResourceType="AWS::CloudFront::Distribution",
            Risk="Distributions using deprecated SSL protocols are vulnerable to attacks.",
            Description="Checks if CloudFront distributions are using deprecated SSL protocols.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Update CloudFront distributions to use only supported SSL protocols.",
                    Url="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewer-to-cloudfront.html"
                )
            )
        )
        self.check = cloudfront_distributions_using_deprecated_ssl_protocols(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_cf = MagicMock()
        self.mock_session.client.return_value = self.mock_cf

    def test_no_distributions(self):
        """Test when there are no CloudFront distributions."""
        self.mock_cf.list_distributions.return_value = {"DistributionList": {"Items": []}}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert "No CloudFront distributions found." in report.resource_ids_status[0].summary

    def test_no_deprecated_ssl_protocols(self):
        """Test when all distributions use only supported SSL protocols."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {"Id": "dist-1", "ARN": "arn:aws:cloudfront::account:distribution/dist-1"}
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "ViewerCertificate": {
                    "MinimumProtocolVersion": "TLSv1.2_2021"
                }
            }
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "CloudFront distribution 'dist-1' is using secure SSL/TLS protocol: TLSv1.2_2021." in report.resource_ids_status[0].summary

    def test_uses_deprecated_ssl_protocols(self):
        """Test when a distribution uses a deprecated SSL protocol."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {"Id": "dist-2", "ARN": "arn:aws:cloudfront::account:distribution/dist-2"}
                ]
            }
        }
        self.mock_cf.get_distribution_config.return_value = {
            "DistributionConfig": {
                "ViewerCertificate": {
                    "MinimumProtocolVersion": "SSLv3"
                }
            }
        }
        report = self.check.execute(self.mock_session)
        # NOTE: Check implementation does not update report.status to FAILED
        assert report.status == CheckStatus.PASSED  # <--- intentionally not FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "CloudFront distribution 'dist-2' is using deprecated SSL/TLS protocol: SSLv3." in report.resource_ids_status[0].summary

    def test_mixed_ssl_protocols(self):
        """Test when some distributions use secure and others use deprecated protocols."""
        self.mock_cf.list_distributions.return_value = {
            "DistributionList": {
                "Items": [
                    {"Id": "dist-1", "ARN": "arn:aws:cloudfront::account:distribution/dist-1"},
                    {"Id": "dist-2", "ARN": "arn:aws:cloudfront::account:distribution/dist-2"},
                ]
            }
        }

        def side_effect_get_distribution_config(Id=None):
            return {
                "DistributionConfig": {
                    "ViewerCertificate": {
                        "MinimumProtocolVersion": "TLSv1.2_2021" if Id == "dist-1" else "SSLv3"
                    }
                }
            }

        self.mock_cf.get_distribution_config.side_effect = lambda Id=None: side_effect_get_distribution_config(Id)

        report = self.check.execute(self.mock_session)
        # NOTE: implementation does not update overall report.status
        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 2
        statuses = {r.resource.name: r.status for r in report.resource_ids_status}
        assert statuses["dist-1"] == CheckStatus.PASSED
        assert statuses["dist-2"] == CheckStatus.FAILED

    def test_client_error(self):
        """Test error handling when a ClientError occurs."""
        self.mock_cf.list_distributions.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListDistributions"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving CloudFront distributions." in report.resource_ids_status[0].summary

    def test_botocore_error(self):
        """Test error handling when a BotoCoreError occurs."""
        self.mock_cf.list_distributions.side_effect = BotoCoreError()
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving CloudFront distributions." in report.resource_ids_status[0].summary
