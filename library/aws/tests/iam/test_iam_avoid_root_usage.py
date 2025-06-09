import pytest
from unittest.mock import MagicMock
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

from library.aws.checks.iam.iam_avoid_root_usage import iam_avoid_root_usage
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)

class TestIamAvoidRootUsage:
    def setup_method(self):
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="iam_avoid_root_usage",
            CheckTitle="Avoid Use of the Root Account",
            CheckType=["security"],
            ServiceName="iam",
            SubServiceName="credential-report",
            ResourceIdTemplate="RootAccount",
            Severity="critical",
            ResourceType="account",
            Risk="The root account has full privileges and should not be used for daily tasks.",
            RelatedUrl="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="Avoid using the root user. Create an IAM user with necessary permissions.",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Avoid using the root account except for initial setup.",
                    Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
                )
            ),
            Description="Checks if the root account was used in the past 7 days.",
            Categories=["security", "iam"]
        )

        self.check = iam_avoid_root_usage(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def generate_credential_report(self, password_last_used="N/A", access_key_1_last_used="N/A", access_key_2_last_used="N/A"):
        header = "user,password_last_used,access_key_1_last_used,access_key_2_last_used"
        row = f"<root_account>,{password_last_used},{access_key_1_last_used},{access_key_2_last_used}"
        report = f"{header}\n{row}".encode("utf-8")
        return {"Content": report}

    def test_root_account_used_recently(self):
        recent_time = (datetime.now(timezone.utc) - timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        self.mock_client.get_credential_report.return_value = self.generate_credential_report(access_key_1_last_used=recent_time)

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(r.summary is not None and "Root account was accessed" in r.summary for r in report.resource_ids_status)

    def test_root_account_used_long_ago(self):
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        self.mock_client.get_credential_report.return_value = self.generate_credential_report(password_last_used=old_time)

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert any(r.summary is not None and "Root account last accessed" in r.summary for r in report.resource_ids_status)

    def test_root_account_usage_unknown(self):
        self.mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
        self.mock_client.get_credential_report.return_value = self.generate_credential_report()

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.SKIPPED
        assert any(r.summary is not None and "No valid last access timestamp found" in r.summary for r in report.resource_ids_status)

    def test_credential_report_generation_failure(self):
        self.mock_client.generate_credential_report.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "GenerateCredentialReport"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert any(r.summary is not None and "IAM API request failed" in r.summary for r in report.resource_ids_status)
