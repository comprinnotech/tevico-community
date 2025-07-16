import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.secretsmanager.secrets_manager_automatic_rotation_enabled import secrets_manager_automatic_rotation_enabled
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)


class TestSecretsManagerAutomaticRotation:
    """Test cases for Secrets Manager automatic rotation check."""

    def setup_method(self):
        """Set up mock client, session, and check instance."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="secrets_manager_automatic_rotation_enabled",
            CheckTitle="Ensure Secrets Manager secrets have automatic rotation enabled.",
            CheckType=["security"],
            ServiceName="secretsmanager",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:secretsmanager:region:account-id:secret",
            Severity="medium",
            ResourceType="AwsSecretsManagerSecret",
            Description="Ensure that automatic rotation is enabled for all Secrets Manager secrets.",
            Risk="Secrets without automatic rotation are at risk of stale credentials, increasing the chance of unauthorized access.",
            RelatedUrl="https://docs.aws.amazon.com/secretsmanager/latest/userguide/enable-rotation.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws secretsmanager rotate-secret --secret-id <secret-id>",
                    Terraform=None,
                    NativeIaC=None,
                    Other="https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/SecretsManager/secrets-manager-enable-auto-rotation.html"
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable automatic rotation for all Secrets Manager secrets.",
                    Url="https://docs.aws.amazon.com/secretsmanager/latest/userguide/enable-rotation.html"
                )
            ),
            Categories=["security"],
        )

        self.check = secrets_manager_automatic_rotation_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client
        self.mock_client.exceptions = MagicMock()  # for future expansion if needed

    def test_all_secrets_have_rotation_enabled(self):
        """Test when all secrets have rotation enabled."""
        self.mock_client.list_secrets.return_value = {
            "SecretList": [
                {"ARN": "arn:aws:secretsmanager:region:account-id:secret/secret1", "Name": "secret1", "RotationEnabled": True},
                {"ARN": "arn:aws:secretsmanager:region:account-id:secret/secret2", "Name": "secret2", "RotationEnabled": True},
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 2
        assert all(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert all("Automatic rotation is enabled" in r.summary for r in report.resource_ids_status)

    def test_some_secrets_have_rotation_disabled(self):
        """Test when some secrets have rotation disabled."""
        self.mock_client.list_secrets.return_value = {
            "SecretList": [
                {"ARN": "arn:aws:secretsmanager:region:account-id:secret/secret1", "Name": "secret1", "RotationEnabled": True},
                {"ARN": "arn:aws:secretsmanager:region:account-id:secret/secret2", "Name": "secret2", "RotationEnabled": False},
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        assert any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        assert any(r.status == CheckStatus.PASSED for r in report.resource_ids_status)

    def test_all_secrets_have_rotation_disabled(self):
        """Test when all secrets have rotation disabled."""
        self.mock_client.list_secrets.return_value = {
            "SecretList": [
                {"ARN": "arn:aws:secretsmanager:region:account-id:secret/secret1", "Name": "secret1", "RotationEnabled": False},
                {"ARN": "arn:aws:secretsmanager:region:account-id:secret/secret2", "Name": "secret2", "RotationEnabled": False},
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        assert all(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        assert all("NOT enabled" in r.summary for r in report.resource_ids_status)

    def test_no_secrets_exist(self):
        """Test when no secrets exist in the account."""
        self.mock_client.list_secrets.return_value = {"SecretList": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No secrets found" in report.resource_ids_status[0].summary

    def test_client_error_handling(self):
        """Test error handling when a ClientError occurs."""
        self.mock_client.list_secrets.side_effect = ClientError(
            error_response={"Error": {"Code": "AccessDeniedException", "Message": "Access Denied"}},
            operation_name="ListSecrets"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving secrets from Secrets Manager" in report.resource_ids_status[0].summary
