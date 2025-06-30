"""
Test for Route53 domains privacy protection enabled check.
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.route53.route53_domains_privacy_protection_enabled import route53_domains_privacy_protection_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestRoute53DomainsPrivacyProtectionEnabled:
    """Test cases for Route53 domains privacy protection check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="route53_domains_privacy_protection_enabled",
            CheckTitle="Ensure Route53 domains have privacy protection enabled",
            CheckType=["Security", "Privacy"],
            ServiceName="route53",
            SubServiceName="domains",
            ResourceIdTemplate="arn:aws:route53domains:::{domain_name}",
            Severity="medium",
            ResourceType="AwsRoute53Domain",
            Description="Ensure all Route53 domains have complete privacy protection enabled for Admin, Registrant, and Technical contacts.",
            Risk="Without privacy protection enabled, personal contact information is published to the public WHOIS database, potentially exposing domain owners to spam, phishing, identity theft, and social engineering attacks.",
            RelatedUrl="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-privacy-protection.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws route53domains update-domain-contact-privacy --domain-name example.com --admin-privacy --registrant-privacy --tech-privacy",
                    Terraform='''resource "aws_route53domains_registered_domain" "example" {
  domain_name = "example.com"
  admin_privacy = true
  registrant_privacy = true
  tech_privacy = true
}''',
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable privacy protection for all contact types (Admin, Registrant, and Technical) for each Route53 domain.",
                    Url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-privacy-protection.html"
                )
            ),
            Categories=["security", "privacy"],
            DependsOn=[],
            RelatedTo=[],
            Notes="Privacy protection is available for most TLDs but may not be available for all domain extensions."
        )

        self.check = route53_domains_privacy_protection_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_no_domains_found(self):
        """Test when no Route53 domains are present."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [{"Domains": []}]
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No Route53 domains found." in report.resource_ids_status[0].summary

    def test_domain_with_complete_privacy_protection(self):
        """Test when a domain has full privacy protection enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Domains": [{"DomainName": "secure-example.com"}]}
        ]
        self.mock_client.get_domain_detail.return_value = {
            "AdminPrivacy": True,
            "RegistrantPrivacy": True,
            "TechPrivacy": True
        }
        report = self.check.execute(self.mock_session)
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "complete privacy protection enabled" in report.resource_ids_status[0].summary

    def test_domain_with_partial_privacy_protection(self):
        """Test when a domain is missing some privacy protection roles."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {"Domains": [{"DomainName": "partial-example.com"}]}
        ]
        self.mock_client.get_domain_detail.return_value = {
            "AdminPrivacy": True,
            "RegistrantPrivacy": False,
            "TechPrivacy": True
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Registrant" in report.resource_ids_status[0].summary

    def test_multiple_domains_mixed_results(self):
        """Test multiple domains with both passing and failing privacy settings."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Domains": [
                    {"DomainName": "secure.com"},
                    {"DomainName": "insecure.com"}
                ]
            }
        ]

        def get_domain_detail_side_effect(DomainName):
            if DomainName == "secure.com":
                return {
                    "AdminPrivacy": True,
                    "RegistrantPrivacy": True,
                    "TechPrivacy": True
                }
            else:
                return {
                    "AdminPrivacy": False,
                    "RegistrantPrivacy": False,
                    "TechPrivacy": True
                }

        self.mock_client.get_domain_detail.side_effect = get_domain_detail_side_effect
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        passed = [r for r in report.resource_ids_status if r.status == CheckStatus.PASSED]
        failed = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]
        assert len(passed) == 1
        assert len(failed) == 1
        assert "missing privacy protection" in failed[0].summary
