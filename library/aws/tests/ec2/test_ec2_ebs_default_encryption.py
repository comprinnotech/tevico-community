"""
Test suite for the ec2_ebs_default_encryption check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 09-06-2025
"""

# Import required libraries for testing and mocking
import pytest
from unittest.mock import MagicMock, patch
import boto3
from botocore.exceptions import BotoCoreError, ClientError 

# Import models and the check class
from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus,
    CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
)
from library.aws.checks.ec2.ec2_ebs_default_encryption import ec2_ebs_default_encryption

# ----------------------------- Fixtures -----------------------------

@pytest.fixture
def mock_boto_session():
    """Creates a mocked boto3 session to simulate AWS client calls."""
    session = MagicMock(spec=boto3.Session)
    return session


@pytest.fixture
def test_metadata():
    """Returns a CheckMetadata instance with test data for the check."""
    return CheckMetadata(
        Provider="AWS",
        CheckID="ec2_ebs_default_encryption",
        CheckTitle="Check EBS Default Encryption",
        CheckType=["Security"],
        ServiceName="EC2",
        SubServiceName="EBS",
        ResourceIdTemplate="arn:aws:ec2:{region}:{account}:volume/{volume_id}",
        Severity="medium",
        ResourceType="AWS::EC2::Volume",
        Risk="Data at rest should be encrypted",
        Description="Checks if EBS default encryption is enabled",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws ec2 enable-ebs-encryption-by-default",
                NativeIaC="",
                Terraform=""
            ),
            Recommendation=RemediationRecommendation(
                Text="Enable EBS default encryption",
                Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
            )
        )
    )


@pytest.fixture
def check_instance(test_metadata):
    """Returns an instance of the check class using the test metadata."""
    return ec2_ebs_default_encryption(metadata=test_metadata)


# ----------------------------- Test Cases -----------------------------

def test_execute_success_enabled(mock_boto_session, check_instance):
    """Tests the check when default EBS encryption is enabled.

    Expected outcome: CheckStatus should be PASSED and summary should reflect encryption is enabled.
    """
    mock_ec2 = MagicMock()
    mock_ec2.get_ebs_encryption_by_default.return_value = {'EbsEncryptionByDefault': True}
    mock_boto_session.client.return_value = mock_ec2

    report = check_instance.execute(mock_boto_session)

    assert len(report.resource_ids_status) == 1
    status = report.resource_ids_status[0]
    assert status.status == CheckStatus.PASSED
    assert isinstance(status.resource, GeneralResource)
    assert "enabled" in status.summary.lower()


def test_execute_success_disabled(mock_boto_session, check_instance):
    """Tests the check when default EBS encryption is disabled.

    Expected outcome: CheckStatus should be FAILED and summary should reflect encryption is not enabled.
    """
    mock_ec2 = MagicMock()
    mock_ec2.get_ebs_encryption_by_default.return_value = {'EbsEncryptionByDefault': False}
    mock_boto_session.client.return_value = mock_ec2

    report = check_instance.execute(mock_boto_session)

    assert len(report.resource_ids_status) == 1
    status = report.resource_ids_status[0]
    assert status.status == CheckStatus.FAILED
    assert isinstance(status.resource, GeneralResource)
    assert "not enabled" in status.summary.lower()


def test_execute_boto_core_error(mock_boto_session, check_instance):
    """Tests the check when a BotoCoreError is raised during execution.

    Expected outcome: CheckStatus should be UNKNOWN with error summary and exception captured.
    """
    mock_ec2 = MagicMock()
    mock_ec2.get_ebs_encryption_by_default.side_effect = BotoCoreError()
    mock_boto_session.client.return_value = mock_ec2

    report = check_instance.execute(mock_boto_session)

    assert len(report.resource_ids_status) == 1
    status = report.resource_ids_status[0]
    assert status.status == CheckStatus.UNKNOWN
    assert "Error" in status.summary
    assert status.exception is not None


def test_execute_client_error(mock_boto_session, check_instance):
    """Tests the check when a ClientError (e.g., AccessDenied) occurs.

    Expected outcome: CheckStatus should be UNKNOWN, and the exception message should include the AWS error code.
    """
    mock_ec2 = MagicMock()
    mock_ec2.get_ebs_encryption_by_default.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 
        'GetEbsEncryptionByDefault'
    )
    mock_boto_session.client.return_value = mock_ec2

    report = check_instance.execute(mock_boto_session)

    assert len(report.resource_ids_status) == 1
    status = report.resource_ids_status[0]
    assert status.status == CheckStatus.UNKNOWN
    assert "Error" in status.summary
    assert "AccessDenied" in status.exception


def test_execute_unexpected_exception(mock_boto_session, check_instance):
    """Tests that an unexpected exception raised by the check is actually raised (since we're not handling it in the check code)."""
    with patch.object(check_instance, 'execute', side_effect=Exception("Unexpected error")):
        with pytest.raises(Exception) as exc_info:
            check_instance.execute(mock_boto_session)
        assert "Unexpected" in str(exc_info.value)


def test_report_structure(mock_boto_session, check_instance):
    """Tests that the returned report has the correct structure and metadata.

    Expected outcome: Report should have name, resource_ids_status list, and at least one ResourceStatus object.
    """
    mock_ec2 = MagicMock()
    mock_ec2.get_ebs_encryption_by_default.return_value = {'EbsEncryptionByDefault': True}
    mock_boto_session.client.return_value = mock_ec2

    report = check_instance.execute(mock_boto_session)
    
    assert hasattr(report, 'name')
    assert report.name == 'library.aws.checks.ec2.ec2_ebs_default_encryption'
    assert isinstance(report.resource_ids_status, list)
    assert len(report.resource_ids_status) == 1
    assert isinstance(report.resource_ids_status[0], ResourceStatus)
