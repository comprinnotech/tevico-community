import pytest
from unittest.mock import MagicMock, patch
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

    @patch("boto3.Session.client")
    def test_no_certificates(self, mock_client):
        """Test when there are no ACM certificates."""
        self.mock_acm.list_certificates.return_value = {"CertificateSummaryList": []}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].summary is not None
        assert "No ACM certificates found" in report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_transparency_logs_enabled(self, mock_client):
        """Test when all certificates have transparency logs enabled."""
        self.mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:region:account:certificate/cert-1"}]
        }
        self.mock_acm.describe_certificate.return_value = {
            "Certificate": {"Options": {"CertificateTransparencyLoggingPreference": "ENABLED"}}
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].summary is not None
        assert "has transparency logging enabled" in report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_transparency_logs_disabled(self, mock_client):
        """Test when a certificate has transparency logs disabled."""
        self.mock_acm.list_certificates.return_value = {
            "CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:region:account:certificate/cert-2"}]
        }
        self.mock_acm.describe_certificate.return_value = {
            "Certificate": {"Options": {"CertificateTransparencyLoggingPreference": "DISABLED"}}
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].summary is not None
        assert "has transparency logging disabled" in report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_client_error(self, mock_client):
        """Test error handling when a ClientError occurs."""
        self.mock_acm.list_certificates.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListCertificates")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].summary is not None
        # Accept any error message, just check it's present
        assert report.resource_ids_status[0].summary