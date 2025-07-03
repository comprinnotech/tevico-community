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


@pytest.fixture
def test_metadata():
    return CheckMetadata(
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


@pytest.fixture
def check_instance(test_metadata):
    return acm_certificates_expiration_check(metadata=test_metadata)


def get_mock_session(mock_acm):
    mock_session = MagicMock()
    mock_session.client.return_value = mock_acm
    return mock_session


def test_no_certificates(check_instance):
    mock_acm = MagicMock()
    mock_acm.list_certificates.return_value = {"CertificateSummaryList": []}

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.NOT_APPLICABLE
    assert "No ACM certificates found" in report.resource_ids_status[0].summary


def test_certificate_expired(check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/expired"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    expired_date = datetime.now(timezone.utc) - timedelta(days=2)
    mock_acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": expired_date}
    }

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].resource.arn == cert_arn
    assert "already expired" in report.resource_ids_status[0].summary


def test_certificate_expiring_soon(check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/soon"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    soon_date = datetime.now(timezone.utc) + timedelta(days=3, minutes=5)
    mock_acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": soon_date}
    }

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].resource.arn == cert_arn
    assert "expires in 3 days" in report.resource_ids_status[0].summary


def test_certificate_valid_longer(check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/valid"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    valid_date = datetime.now(timezone.utc) + timedelta(days=30, minutes=5)
    mock_acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": valid_date}
    }

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].resource.arn == cert_arn
    assert "valid for 30 more days" in report.resource_ids_status[0].summary


def test_describe_certificate_error(check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/error"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    mock_acm.describe_certificate.side_effect = Exception("Describe error")

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].resource.arn == cert_arn
    assert "Error describing certificate" in report.resource_ids_status[0].summary


def test_list_certificates_error(check_instance):
    mock_acm = MagicMock()
    mock_acm.list_certificates.side_effect = Exception("List error")

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "Error fetching ACM certificates" in report.resource_ids_status[0].summary
