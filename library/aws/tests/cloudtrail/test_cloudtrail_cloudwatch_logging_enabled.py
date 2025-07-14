import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.cloudtrail.cloudtrail_cloudwatch_logging_enabled import (
    cloudtrail_cloudwatch_logging_enabled,
)

class TestCloudTrailCloudWatchLoggingEnabled:
    """Test cases for CloudTrail CloudWatch Logging Enabled check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="cloudtrail_cloudwatch_logging_enabled",
            CheckTitle="CloudTrail trails have CloudWatch logging enabled",
            CheckType=["Security"],
            ServiceName="CloudTrail",
            SubServiceName="Trail",
            ResourceIdTemplate="arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}",
            Severity="medium",
            ResourceType="AWS::CloudTrail::Trail",
            Risk="Trails without CloudWatch logging may lack real-time monitoring.",
            Description="Checks if CloudTrail trails have CloudWatch logging enabled.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Enable CloudWatch logging for CloudTrail trails.",
                    Url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html"
                )
            )
        )
        self.check = cloudtrail_cloudwatch_logging_enabled(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_ct = MagicMock()
        self.mock_session.client.return_value = self.mock_ct

    def test_no_trails(self):
        """Test when there are no CloudTrail trails."""
        self.mock_ct.describe_trails.return_value = {"trailList": []}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert "No CloudTrail trails found." in report.resource_ids_status[0].summary

    def test_cloudwatch_logging_enabled(self):
        """Test when a trail has CloudWatch logging enabled."""
        self.mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "trail-1",
                    "TrailARN": "arn:aws:cloudtrail:region:account:trail/trail-1",
                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:region:account:log-group:group"
                }
            ]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "is logging to CloudWatch" in report.resource_ids_status[0].summary

    def test_cloudwatch_logging_disabled(self):
        """Test when a trail does not have CloudWatch logging enabled."""
        self.mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "trail-2",
                    "TrailARN": "arn:aws:cloudtrail:region:account:trail/trail-2"
                }
            ]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "is NOT logging to CloudWatch" in report.resource_ids_status[0].summary

    def test_mixed_trail_states(self):
        """Test when some trails have logging enabled and some do not."""
        self.mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "trail-1",
                    "TrailARN": "arn:aws:cloudtrail:region:account:trail/trail-1",
                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:region:account:log-group:group"
                },
                {
                    "Name": "trail-2",
                    "TrailARN": "arn:aws:cloudtrail:region:account:trail/trail-2"
                }
            ]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert report.resource_ids_status[1].status == CheckStatus.FAILED

    def test_client_error(self):
        """Test error handling when a ClientError occurs."""
        self.mock_ct.describe_trails.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "DescribeTrails"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving CloudTrail details." in report.resource_ids_status[0].summary

    def test_botocore_error(self):
        """Test error handling when a BotoCoreError occurs."""
        self.mock_ct.describe_trails.side_effect = BotoCoreError()
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving CloudTrail details." in report.resource_ids_status[0].summary
