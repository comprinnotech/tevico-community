import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
from library.aws.checks.acm.acm_certificates_expiration_check import acm_certificates_expiration_check

class TestAcmCertificatesExpirationCheck:
    """Test cases for ACM certificates expiration check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="aws",
            CheckID="acm_certificates_expiration_check",
            CheckTitle="Ensure ACM certificates are not expiring soon",
            CheckType=["Data Protection"],
            ServiceName="acm",
            SubServiceName="",
            ResourceIdTemplate="arn:partition:acm:region:account-id:resource/resource-id",
            Severity="high",
            ResourceType="AwsCertificateManagerCertificate",
            Risk="Expiring certificates may lead to downtime, service disruptions, or trust issues if not renewed in time.",
            Description="Checks if ACM certificates are nearing expiration, which could result in service disruptions if not renewed.",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws acm renew-certificate --certificate-arn <certificate-arn>",
                    NativeIaC="",
                    Terraform="",
                    Other=""
                ),
                Recommendation=RemediationRecommendation(
                    Text="Regularly monitor and renew expiring ACM certificates to avoid service disruptions.",
                    Url="https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-expiration.html"
                )
            ),
            RelatedUrl="https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-expiration.html",
            Categories=["Data Protection"],
            DependsOn=[],
            RelatedTo=[],
            Notes="Data Protection"
        )
        self.check = acm_certificates_expiration_check(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    @patch("boto3.Session.client")
    def test_no_certificates(self, mock_client):
        self.mock_client.list_certificates.return_value = {"CertificateSummaryList": []}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].summary is not None
        assert "No ACM certificates found" in report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_certificate_expired(self, mock_client):
        cert_arn = "arn:aws:acm:region:account:certificate/expired"
        self.mock_client.list_certificates.return_value = {"CertificateSummaryList": [{"CertificateArn": cert_arn}]}
        expired_date = datetime.now(timezone.utc) - timedelta(days=2)
        self.mock_client.describe_certificate.return_value = {"Certificate": {"NotAfter": expired_date}}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert any(r.summary is not None and "already expired" in r.summary for r in report.resource_ids_status)

    @patch("boto3.Session.client")
    def test_certificate_expiring_soon(self, mock_client):
        cert_arn = "arn:aws:acm:region:account:certificate/soon"
        self.mock_client.list_certificates.return_value = {"CertificateSummaryList": [{"CertificateArn": cert_arn}]}
        expiring_date = datetime.now(timezone.utc) + timedelta(days=3)
        self.mock_client.describe_certificate.return_value = {"Certificate": {"NotAfter": expiring_date}}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert any(r.summary is not None and "expires in" in r.summary for r in report.resource_ids_status)

    @patch("boto3.Session.client")
    def test_certificate_valid(self, mock_client):
        cert_arn = "arn:aws:acm:region:account:certificate/valid"
        self.mock_client.list_certificates.return_value = {"CertificateSummaryList": [{"CertificateArn": cert_arn}]}
        valid_date = datetime.now(timezone.utc) + timedelta(days=30)
        self.mock_client.describe_certificate.return_value = {"Certificate": {"NotAfter": valid_date}}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert any(r.summary is not None and "is valid for" in r.summary for r in report.resource_ids_status)

    @patch("boto3.Session.client")
    def test_describe_certificate_error(self, mock_client):
        cert_arn = "arn:aws:acm:region:account:certificate/error"
        self.mock_client.list_certificates.return_value = {"CertificateSummaryList": [{"CertificateArn": cert_arn}]}
        self.mock_client.describe_certificate.side_effect = Exception("Describe error")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert any(r.summary is not None and "Error describing certificate" in r.summary for r in report.resource_ids_status)

    @patch("boto3.Session.client")
    def test_list_certificates_error(self, mock_client):
        self.mock_client.list_certificates.side_effect = Exception("List error")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert any(r.summary is not None and "Error fetching ACM certificates" in r.summary for r in report.resource_ids_status)
