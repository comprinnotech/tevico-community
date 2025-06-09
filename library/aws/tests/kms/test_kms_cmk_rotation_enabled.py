import pytest
from unittest.mock import MagicMock
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.kms.kms_cmk_rotation_enabled import kms_cmk_rotation_enabled


class TestKMSCMKRotationEnabled:

    def setup_method(self):
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="kms_cmk_rotation_enabled",
            CheckTitle="Ensure that automatic rotation is enabled for KMS Customer Managed Keys (CMKs)",
            CheckType=["security", "compliance"],
            ServiceName="kms",
            SubServiceName="key",
            ResourceIdTemplate="",
            Severity="medium",
            ResourceType="AWS::KMS::Key",
            Risk="If rotation is not enabled, the key material may become less secure over time.",
            RelatedUrl="https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws kms enable-key-rotation --key-id <key-id>",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None,
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable automatic rotation of CMKs to enhance security.",
                    Url="https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
                )
            ),
            Description="Checks whether rotation is enabled for customer managed CMKs.",
            Categories=["encryption", "security", "compliance"]
        )
        self.check = kms_cmk_rotation_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_kms_client = MagicMock()
        self.mock_session.client.return_value = self.mock_kms_client

    def test_rotation_enabled_for_customer_cmk(self):
        # Mock list_keys response with one key
        self.mock_kms_client.list_keys.side_effect = [
            {"Keys": [{"KeyId": "key-123"}], "NextMarker": None}
        ]
        # Mock describe_key for enabled customer key
        self.mock_kms_client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-123",
                "Arn": "arn:aws:kms:region:acct:key/key-123",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
            }
        }
        # Mock get_key_rotation_status returning rotation enabled
        self.mock_kms_client.get_key_rotation_status.return_value = {
            "KeyRotationEnabled": True
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert any(
            r.summary and "rotation is enabled" in r.summary.lower()
            for r in report.resource_ids_status
        )

    def test_rotation_not_enabled_for_customer_cmk(self):
        # Mock list_keys response with one key
        self.mock_kms_client.list_keys.side_effect = [
            {"Keys": [{"KeyId": "key-456"}], "NextMarker": None}
        ]
        # Mock describe_key for enabled customer key
        self.mock_kms_client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-456",
                "Arn": "arn:aws:kms:region:acct:key/key-456",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
            }
        }
        # Mock get_key_rotation_status returning rotation disabled
        self.mock_kms_client.get_key_rotation_status.return_value = {
            "KeyRotationEnabled": False
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(
            r.summary and "rotation is not enabled" in r.summary.lower()
            for r in report.resource_ids_status
        )

    def test_non_customer_or_disabled_keys_are_ignored(self):
        # Mock list_keys response with keys that are AWS-managed or disabled
        self.mock_kms_client.list_keys.side_effect = [
            {"Keys": [{"KeyId": "key-789"}, {"KeyId": "key-000"}], "NextMarker": None}
        ]
        # First key is AWS-managed
        # Second key is customer but disabled
        def describe_key_side_effect(KeyId):
            if KeyId == "key-789":
                return {
                    "KeyMetadata": {
                        "KeyId": "key-789",
                        "Arn": "arn:aws:kms:region:acct:key/key-789",
                        "KeyManager": "AWS",
                        "KeyState": "Enabled",
                    }
                }
            elif KeyId == "key-000":
                return {
                    "KeyMetadata": {
                        "KeyId": "key-000",
                        "Arn": "arn:aws:kms:region:acct:key/key-000",
                        "KeyManager": "CUSTOMER",
                        "KeyState": "Disabled",
                    }
                }
            else:
                return {}

        self.mock_kms_client.describe_key.side_effect = describe_key_side_effect

        report = self.check.execute(self.mock_session)

        # Since no eligible keys found, report status should be NOT_APPLICABLE or PASSED
        # But per your original check logic, no eligible keys means NOT_APPLICABLE
        assert report.status == CheckStatus.NOT_APPLICABLE or report.status == CheckStatus.PASSED
        # The resource_ids_status should have at least one entry for no customer-managed keys
        assert any(
            r.summary and "no customer-managed cmks found" in r.summary.lower()
            for r in report.resource_ids_status
        ) or len(report.resource_ids_status) == 0

    def test_error_fetching_keys(self):
        self.mock_kms_client.list_keys.side_effect = Exception("Simulated API failure")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(
            r.summary and "error fetching kms keys" in r.summary.lower()
            for r in report.resource_ids_status
        )

    def test_error_retrieving_rotation_status(self):
        self.mock_kms_client.list_keys.side_effect = [
            {"Keys": [{"KeyId": "key-999"}], "NextMarker": None}
        ]
        self.mock_kms_client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-999",
                "Arn": "arn:aws:kms:region:acct:key/key-999",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
            }
        }
        self.mock_kms_client.get_key_rotation_status.side_effect = Exception(
            "Rotation status error"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(
            r.summary and "error retrieving rotation status" in r.summary.lower()
            for r in report.resource_ids_status
        )
