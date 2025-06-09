import pytest
from unittest.mock import MagicMock
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.kms.kms_cmk_are_used import kms_cmk_are_used


class TestKMSCMKsAreUsed:

    def setup_method(self):
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="kms_cmk_are_used",
            CheckTitle="Ensure that KMS Customer Managed Keys (CMKs) are used",
            CheckType=["security", "compliance"],
            ServiceName="kms",
            SubServiceName="key",
            ResourceIdTemplate="",
            Severity="medium",
            ResourceType="AWS::KMS::Key",
            Risk="If Customer Managed Keys are not used, you may lack control over key rotation, deletion, and access.",
            RelatedUrl="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws kms create-key --description 'Customer managed key'",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None,
                ),
                Recommendation=RemediationRecommendation(
                    Text="Use Customer Managed Keys for more granular control over encryption.",
                    Url="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk"
                )
            ),
            Description="Checks whether Customer Managed CMKs exist and are enabled.",
            Categories=["encryption", "security", "compliance"]
        )
        self.check = kms_cmk_are_used(metadata)
        self.mock_session = MagicMock()
        self.mock_kms_client = MagicMock()
        self.mock_session.client.return_value = self.mock_kms_client

    def test_enabled_customer_cmk_exists(self):
        self.mock_kms_client.get_paginator.return_value.paginate.return_value = [
            {"Keys": [{"KeyId": "key-123"}]}
        ]
        self.mock_kms_client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-123",
                "Arn": "arn:aws:kms:region:acct:key/key-123",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled"
            }
        }

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert any(r.summary and "enabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_disabled_customer_cmk_exists(self):
        self.mock_kms_client.get_paginator.return_value.paginate.return_value = [
            {"Keys": [{"KeyId": "key-456"}]}
        ]
        self.mock_kms_client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-456",
                "Arn": "arn:aws:kms:region:acct:key/key-456",
                "KeyManager": "CUSTOMER",
                "KeyState": "Disabled"
            }
        }

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert any(r.summary and "disabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_no_customer_cmk_found(self):
        self.mock_kms_client.get_paginator.return_value.paginate.return_value = [
            {"Keys": [{"KeyId": "key-789"}]}
        ]
        self.mock_kms_client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-789",
                "Arn": "arn:aws:kms:region:acct:key/key-789",
                "KeyManager": "AWS",  # Not customer managed
                "KeyState": "Enabled"
            }
        }

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 0

    def test_kms_api_failure(self):
        self.mock_kms_client.get_paginator.side_effect = Exception("Simulated API failure")

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert any(r.summary and "error fetching kms" in r.summary.lower() for r in report.resource_ids_status)
