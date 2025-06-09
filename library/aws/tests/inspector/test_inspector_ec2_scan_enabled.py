import pytest
from unittest.mock import MagicMock
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
from library.aws.checks.inspector.inspector_ec2_scan_enabled import inspector_ec2_scan_enabled


class TestInspectorEC2ScanEnabled:
    def setup_method(self):
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="inspector_ec2_scan_enabled",
            CheckTitle="Ensure Inspector EC2 standard scan is enabled",
            CheckType=["security"],
            ServiceName="inspector2",
            SubServiceName="ec2",
            ResourceIdTemplate="",
            Severity="high",
            ResourceType="account",
            Risk="If Inspector EC2 scans are not enabled, you might miss vulnerabilities on your EC2 instances.",
            RelatedUrl="https://docs.aws.amazon.com/inspector/latest/user/ec2-scan.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws inspector2 enable --resource-types EC2",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None,
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable Inspector2 EC2 scanning.",
                    Url="https://docs.aws.amazon.com/inspector/latest/user/ec2-scan.html"
                )
            ),
            Description="Checks whether Inspector EC2 standard scan is enabled.",
            Categories=["security", "compliance"]
        )

        self.check = inspector_ec2_scan_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_inspector_client = MagicMock()
        self.mock_sts_client = MagicMock()

        self.mock_session.client.side_effect = lambda service: {
            "inspector2": self.mock_inspector_client,
            "sts": self.mock_sts_client
        }[service]

        self.mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    def set_inspector_response(self, status):
        self.mock_inspector_client.batch_get_account_status.return_value = {
            "accounts": [{
                "resourceState": {
                    "ec2": {
                        "status": status
                    }
                }
            }]
        }

    def test_ec2_scan_enabled(self):
        self.set_inspector_response("ENABLED")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert any(r.summary is not None and "enabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_ec2_scan_disabled(self):
        self.set_inspector_response("DISABLED")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(r.summary is not None and "not enabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_ec2_scan_suspended(self):
        self.set_inspector_response("SUSPENDED")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(r.summary is not None and "suspended" in r.summary.lower() for r in report.resource_ids_status)

    def test_ec2_scan_transitional(self):
        self.set_inspector_response("TRANSITIONING")
        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(r.summary is not None and "transitional" in r.summary.lower() for r in report.resource_ids_status)

    def test_api_failure(self):
        self.mock_inspector_client.batch_get_account_status.side_effect = Exception("Simulated API failure")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(r.summary is not None and "error checking" in r.summary.lower() for r in report.resource_ids_status)
