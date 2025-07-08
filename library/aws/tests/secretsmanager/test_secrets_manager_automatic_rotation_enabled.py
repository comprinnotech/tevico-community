import pytest
from unittest.mock import MagicMock
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
        """Set up mock client, session, and metadata."""

        metadata = CheckMetadata(
            Provider="aws",
            CheckID="secrets_manager_automatic_rotation_enabled",
            CheckTitle="Ensure Secrets Manager secrets have automatic rotation enabled.",
            CheckType=[],
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
            Categories=[],
        )

        self.check = secrets_manager_automatic_rotation_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

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
        assert all(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert len(report.resource_ids_status) == 2

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
        assert any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        assert any(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert len(report.resource_ids_status) == 2

    def test_no_secrets_exist(self):
        """Test when no secrets exist in the account."""
        self.mock_client.list_secrets.return_value = {"SecretList": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No secrets found" in report.resource_ids_status[0].summary

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
        assert all(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        assert len(report.resource_ids_status) == 2
        # TEMP TEST LINE — will remove after confirming Git works
