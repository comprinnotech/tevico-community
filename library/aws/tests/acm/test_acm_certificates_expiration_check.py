import pytest
from unittest.mock import MagicMock, patch
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


@patch("boto3.Session.client")
def test_no_certificates(mock_client, check_instance):
    mock_acm = MagicMock()
    mock_acm.list_certificates.return_value = {"CertificateSummaryList": []}
    mock_client.return_value = mock_acm

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.NOT_APPLICABLE
    assert "No ACM certificates found" in report.resource_ids_status[0].summary


@patch("boto3.Session.client")
def test_certificate_expired(mock_client, check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/expired"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    expired_date = datetime.now(timezone.utc) - timedelta(days=2)
    mock_acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": expired_date}
    }
    mock_client.return_value = mock_acm

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.FAILED
    assert "already expired" in report.resource_ids_status[0].summary


@patch("boto3.Session.client")
def test_certificate_expiring_soon(mock_client, check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/soon"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    # Use 3 days + few minutes to avoid truncation in business logic
    soon_date = datetime.now(timezone.utc) + timedelta(days=3, minutes=5)
    mock_acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": soon_date}
    }
    mock_client.return_value = mock_acm

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.FAILED
    assert "expires in 3 days" in report.resource_ids_status[0].summary

@patch("boto3.Session.client")
def test_certificate_valid_longer(mock_client, check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/valid"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    # Add buffer to avoid edge cut-off
    valid_date = datetime.now(timezone.utc) + timedelta(days=30, minutes=5)
    mock_acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": valid_date}
    }
    mock_client.return_value = mock_acm

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.PASSED
    assert "valid for 30 more days" in report.resource_ids_status[0].summary


@patch("boto3.Session.client")
def test_describe_certificate_error(mock_client, check_instance):
    mock_acm = MagicMock()
    cert_arn = "arn:aws:acm:region:account:certificate/error"
    mock_acm.list_certificates.return_value = {
        "CertificateSummaryList": [{"CertificateArn": cert_arn}]
    }
    mock_acm.describe_certificate.side_effect = Exception("Describe error")
    mock_client.return_value = mock_acm

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
    assert "Error describing certificate" in report.resource_ids_status[0].summary


@patch("boto3.Session.client")
def test_list_certificates_error(mock_client, check_instance):
    mock_acm = MagicMock()
    mock_acm.list_certificates.side_effect = Exception("List error")
    mock_client.return_value = mock_acm

    report = check_instance.execute(get_mock_session(mock_acm))

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "Error fetching ACM certificates" in report.resource_ids_status[0].summary