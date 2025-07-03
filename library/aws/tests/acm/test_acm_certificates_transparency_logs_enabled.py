import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
from library.aws.checks.acm.acm_certificates_transparency_logs_enabled import acm_certificates_transparency_logs_enabled


class TestAcmCertificatesTransparencyLogsEnabled:
    """Test cases for ACM Certificates Transparency Logs Enabled check."""

    def setup_method(self):
        """Set up test method."""
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="acm_certificates_transparency_logs_enabled",
            CheckTitle="Check ACM Certificates Transparency Logs Enabled",
            CheckType=["Security"],
            ServiceName="ACM",
            SubServiceName="Certificate",
            ResourceIdTemplate="arn:aws:acm:{region}:{account}:certificate/{certificate_id}",
            Severity="medium",
            ResourceType="AWS::ACM::Certificate",
            Risk="Certificates without transparency logs may not be trusted.",
            Description="Checks if ACM certificates have transparency logging enabled.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Enable certificate transparency logging for ACM certificates.",
                    Url="https://docs.aws.amazon.com/acm/latest/userguide/acm-concepts.html#concept-transparency"
                )
            )
        )
        self.check = acm_certificates_transparency_logs_enabled(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_acm = MagicMock()
        self.mock_sts = MagicMock()
        self.mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        self.mock_session.client.side_effect = lambda service: self.mock_acm if service == "acm" else self.mock_sts

    def test_no_certificates(self):
        """Test when there are no ACM certificates."""
        self.mock_acm.list_certificates.return_value = {"CertificateSummaryList": []}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].summary is not None
        assert "No ACM certificates found" in report.resource_ids_status[0].summary
        assert not hasattr(report.resource_ids_status[0].resource, "arn")

    def test_transparency_logs_enabled(self):
        """Test when all certificates have transparency logs enabled."""
        cert_arn = "arn:aws:acm:region:account:certificate/cert-1"
        self.mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_acm.describe_certificate.return_value = {
            "Certificate": {"Options": {"CertificateTransparencyLoggingPreference": "ENABLED"}}
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].summary is not None
        assert "has transparency logging enabled" in report.resource_ids_status[0].summary
        assert report.resource_ids_status[0].resource.arn == cert_arn

    def test_transparency_logs_disabled(self):
        """Test when a certificate has transparency logs disabled."""
        cert_arn = "arn:aws:acm:region:account:certificate/cert-2"
        self.mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_acm.describe_certificate.return_value = {
            "Certificate": {"Options": {"CertificateTransparencyLoggingPreference": "DISABLED"}}
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].summary is not None
        assert "has transparency logging disabled" in report.resource_ids_status[0].summary
        assert report.resource_ids_status[0].resource.arn == cert_arn

    def test_client_error(self):
        """Test error handling when list_certificates raises ClientError."""
        self.mock_acm.list_certificates.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListCertificates"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].summary is not None
        assert not hasattr(report.resource_ids_status[0].resource, "arn")

    def test_describe_certificate_error(self):
        """Test error handling when describe_certificate raises ClientError."""
        cert_arn = "arn:aws:acm:region:account:certificate/cert-3"
        self.mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }
        self.mock_acm.describe_certificate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "DescribeCertificate"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].summary is not None
        assert "Error describing certificate" in report.resource_ids_status[0].summary
        assert report.resource_ids_status[0].resource.arn == cert_arn

    def test_no_such_entity_exception(self):
        """Test handling when describe_certificate raises NoSuchEntityException."""
        cert_arn = "arn:aws:acm:region:account:certificate/missing"
        self.mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": cert_arn}]
        }

        class NoSuchEntityException(Exception):
            pass

        self.mock_acm.exceptions = MagicMock()
        self.mock_acm.exceptions.ResourceNotFoundException = NoSuchEntityException
        self.mock_acm.describe_certificate.side_effect = NoSuchEntityException("No such certificate")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].summary is not None
        assert "Error describing certificate" in report.resource_ids_status[0].summary
        assert report.resource_ids_status[0].resource.arn == cert_arn
