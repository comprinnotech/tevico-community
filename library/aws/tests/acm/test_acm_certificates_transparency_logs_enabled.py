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
from library.aws.checks.acm.acm_certificates_transparency_logs_enabled import (
    acm_certificates_transparency_logs_enabled,
)


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
        self.mock_session.client.return_value = self.mock_acm  # Simplified (removed STS)

    def test_no_certificates(self):
        """Test when there are no ACM certificates."""
        self.mock_acm.list_certificates.return_value = {"CertificateSummaryList": []}
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].summary == "No ACM certificates found."
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
        assert report.resource_ids_status[0].summary == f"Certificate {cert_arn} has transparency logging enabled."
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
        assert report.resource_ids_status[0].summary == f"Certificate {cert_arn} has transparency logging disabled."
        assert report.resource_ids_status[0].resource.arn == cert_arn

    def test_client_error(self):
        """Test error handling when list_certificates raises ClientError."""
        self.mock_acm.list_certificates.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListCertificates"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].summary == "Error fetching ACM certificates."
        assert report.resource_ids_status[0].exception is not None
        assert "AccessDenied" in report.resource_ids_status[0].exception

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
        assert report.resource_ids_status[0].summary == f"Error describing certificate {cert_arn}."
        assert "AccessDenied" in report.resource_ids_status[0].exception
        assert report.resource_ids_status[0].resource.arn == cert_arn

    def test_no_such_entity_exception(self):
        """Test handling when describe_certificate raises a ResourceNotFoundException."""
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
        assert report.resource_ids_status[0].summary == f"Error describing certificate {cert_arn}."
        assert "No such certificate" in report.resource_ids_status[0].exception
        assert report.resource_ids_status[0].resource.arn == cert_arn

    def test_paginated_certificates_list(self):
        """Test paginated ACM certificate list."""
        cert_arn_1 = "arn:aws:acm:region:account:certificate/cert-1"
        cert_arn_2 = "arn:aws:acm:region:account:certificate/cert-2"

        self.mock_acm.list_certificates.side_effect = [
            {"CertificateSummaryList": [{"CertificateArn": cert_arn_1}], "NextToken": "token-1"},
            {"CertificateSummaryList": [{"CertificateArn": cert_arn_2}]}
        ]

        self.mock_acm.describe_certificate.side_effect = lambda CertificateArn: {
            "Certificate": {"Options": {"CertificateTransparencyLoggingPreference": "ENABLED"}}
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 2
        assert all(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert report.resource_ids_status[0].resource.arn == cert_arn_1
        assert report.resource_ids_status[1].resource.arn == cert_arn_2
