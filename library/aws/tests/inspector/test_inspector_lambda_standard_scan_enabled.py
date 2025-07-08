import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import (
    CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
)
from library.aws.checks.inspector.inspector_lambda_standard_scan_enabled import inspector_lambda_standard_scan_enabled


class TestInspectorLambdaStandardScanEnabled:
    def setup_method(self):
        """Initialize metadata, check, and mock AWS clients for each test."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="inspector_lambda_standard_scan_enabled",
            CheckTitle="Ensure Inspector Lambda standard scan is enabled",
            CheckType=["security"],
            ServiceName="inspector2",
            SubServiceName="lambda",
            ResourceIdTemplate="",
            Severity="high",
            ResourceType="account",
            Risk="If Inspector Lambda scans are not enabled, you might miss vulnerabilities in Lambda functions.",
            RelatedUrl="https://docs.aws.amazon.com/inspector/latest/user/lambda-scan.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws inspector2 enable --resource-types LAMBDA",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None,
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable Inspector2 Lambda scanning.",
                    Url="https://docs.aws.amazon.com/inspector/latest/user/lambda-scan.html"
                )
            ),
            Description="Checks whether Inspector Lambda standard scan is enabled.",
            Categories=["security", "compliance"]
        )

        self.check = inspector_lambda_standard_scan_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_inspector_client = MagicMock()
        self.mock_sts_client = MagicMock()

        self.mock_session.client.side_effect = lambda service: {
            "inspector2": self.mock_inspector_client,
            "sts": self.mock_sts_client
        }[service]

        self.mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    def set_inspector_response(self, status):
        """Helper to set the inspector2 batch_get_account_status response."""
        self.mock_inspector_client.batch_get_account_status.return_value = {
            "accounts": [{
                "resourceState": {
                    "lambda": {
                        "status": status
                    }
                }
            }]
        }

    def test_lambda_scan_enabled(self):
        """Inspector Lambda scan is enabled."""
        self.set_inspector_response("ENABLED")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert any(r.summary and "enabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_lambda_scan_disabled(self):
        """Inspector Lambda scan is disabled."""
        self.set_inspector_response("DISABLED")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(r.summary and "not enabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_lambda_scan_suspended(self):
        """Inspector Lambda scan is suspended."""
        self.set_inspector_response("SUSPENDED")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(r.summary and "suspended" in r.summary.lower() for r in report.resource_ids_status)

    def test_lambda_scan_unknown_status(self):
        """Inspector Lambda scan is in transitional state (e.g., TRANSITIONING)."""
        self.set_inspector_response("TRANSITIONING")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(r.summary and "transitional" in r.summary.lower() for r in report.resource_ids_status)

    def test_lambda_resource_key_missing(self):
        """Inspector2 returned no 'lambda' key in resourceState."""
        self.mock_inspector_client.batch_get_account_status.return_value = {
            "accounts": [{"resourceState": {}}]  # lambda key missing
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any("transitional" in r.summary.lower() or r.status == CheckStatus.UNKNOWN for r in report.resource_ids_status)

    def test_lambda_scan_client_error(self):
        """Simulate AWS ClientError (e.g., Access Denied)."""
        self.mock_inspector_client.batch_get_account_status.side_effect = ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            operation_name="BatchGetAccountStatus"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any("access denied" in r.summary.lower() for r in report.resource_ids_status)

    def test_api_failure(self):
        """Simulate generic exception while calling Inspector2 API."""
        self.mock_inspector_client.batch_get_account_status.side_effect = Exception("API error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(r.summary and "error checking" in r.summary.lower() for r in report.resource_ids_status)
