import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from library.aws.checks.iam.iam_root_mfa_enabled import iam_root_mfa_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation


class TestIamRootMfaEnabled:
    """Test cases for IAM root MFA enabled check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="iam_root_mfa_enabled",
            CheckTitle="Ensure MFA is enabled for the root account",
            CheckType=["security"],
            ServiceName="iam",
            SubServiceName="root-account",
            ResourceIdTemplate="arn:aws:iam::{account_id}:root",
            Severity="critical",
            ResourceType="iam-user",
            Risk="If the root account is compromised and MFA is not enabled, full access to AWS resources is possible.",
            RelatedUrl="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#root-user-mfa",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws iam enable-mfa-device",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable MFA for the root account from the AWS Management Console.",
                    Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#root-user-mfa"
                )
            ),
            Description="Checks whether MFA is enabled for the root account.",
            Categories=["security", "compliance"]
        )

        self.check = iam_root_mfa_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_mfa_enabled(self):
        """Test when root MFA is enabled."""
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        report_bytes = b"user,mfa_active\n<root_account>,true\n"
        self.mock_client.get_credential_report.return_value = {"Content": report_bytes}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "MFA enabled" in (report.resource_ids_status[0].summary or "")

    def test_mfa_not_enabled(self):
        """Test when root MFA is NOT enabled."""
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        report_bytes = b"user,mfa_active\n<root_account>,false\n"
        self.mock_client.get_credential_report.return_value = {"Content": report_bytes}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does NOT have MFA enabled" in (report.resource_ids_status[0].summary or "")

    @patch("time.sleep", return_value=None)
    def test_report_generation_timeout(self, _):
        """Test timeout while waiting for report generation."""
        self.mock_client.generate_credential_report.return_value = {"State": "IN_PROGRESS"}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "timed out" in (report.resource_ids_status[0].summary or "") or \
               "Failed to generate" in (report.resource_ids_status[0].summary or "")

    def test_empty_credential_report(self):
        """Test handling of an empty credential report."""
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        self.mock_client.get_credential_report.return_value = {"Content": b""}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Failed to generate or retrieve IAM credential report" in (report.resource_ids_status[0].summary or "")

    def test_missing_mfa_column(self):
        """Test when mfa_active column is missing."""
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        content = b"user\n<root_account>\n"
        self.mock_client.get_credential_report.return_value = {"Content": content}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does NOT have MFA enabled" in (report.resource_ids_status[0].summary or "")

    def test_client_error(self):
        """Test error handling with botocore ClientError."""
        self.mock_client.generate_credential_report.side_effect = ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            operation_name="GenerateCredentialReport"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Denied" in (report.resource_ids_status[0].exception or "")
