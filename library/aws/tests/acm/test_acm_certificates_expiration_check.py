import pytest
from unittest.mock import MagicMock
from datetime import datetime, timedelta, timezone

from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.acm.acm_certificates_expiration_check import acm_certificates_expiration_check


class TestAcmCertificatesExpirationCheck:
    """Test cases for ACM certificate expiration check."""

    def setup_method(self):
        """Set up test metadata and mocked session."""
        metadata = CheckMetadata(
            Provider="AWS",
            CheckID="acm_certificates_expiration_check",
            CheckTitle="Check ACM Certificate Expiration",
            CheckType=["Security"],
            ServiceName="ACM",
            SubServiceName="Certificate",
            ResourceIdTemplate="arn:aws:acm:{region}:{account}:certificate/{certificate_id}",
            Severity="medium",
            ResourceType="AWS::ACM::Certificate",
            Risk="Expired certificates can cause outages.",
            Description="Checks for ACM certificates that are expired or expiring soon.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Renew or replace expiring ACM certificates.",
                    Url="https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html"
                )
            )
        )

        self.check = acm_certificates_expiration_check(metadata=metadata)
        self.mock_client = MagicMock()

        # Wrap session so .client('acm') returns mock client
        self.mock_session = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_no_certificates(self):
        self.mock_client.list_certificates.return_value = {"CertificateSummaryList": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert "No ACM certificates found" in report.resource_ids_status[0].summary

    def test_certificate_expired(self):
        cert_arn = "arn:aws:acm:region:account:certificate/expired"
        self.mock_client.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_client.describe_certificate.return_value = {
            "Certificate": {"NotAfter": datetime.now(timezone.utc) - timedelta(days=2)}
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].resource.arn == cert_arn
        assert "already expired" in report.resource_ids_status[0].summary

    def test_certificate_expiring_soon(self):
        cert_arn = "arn:aws:acm:region:account:certificate/soon"
        self.mock_client.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_client.describe_certificate.return_value = {
            "Certificate": {"NotAfter": datetime.now(timezone.utc) + timedelta(days=3, minutes=5)}
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].resource.arn == cert_arn
        assert "expires in 3 days" in report.resource_ids_status[0].summary

    def test_certificate_valid_longer(self):
        cert_arn = "arn:aws:acm:region:account:certificate/valid"
        self.mock_client.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_client.describe_certificate.return_value = {
            "Certificate": {"NotAfter": datetime.now(timezone.utc) + timedelta(days=30, minutes=5)}
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].resource.arn == cert_arn
        assert "valid for 30 more days" in report.resource_ids_status[0].summary

    def test_describe_certificate_error(self):
        cert_arn = "arn:aws:acm:region:account:certificate/error"
        self.mock_client.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_client.describe_certificate.side_effect = Exception("Describe error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].resource.arn == cert_arn
        assert "Error describing certificate" in report.resource_ids_status[0].summary

    def test_list_certificates_error(self):
        self.mock_client.list_certificates.side_effect = Exception("List error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Error fetching ACM certificates" in report.resource_ids_status[0].summary
