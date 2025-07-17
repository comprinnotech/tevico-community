import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.vpc.vpc_flowlogs_enable_logging import vpc_flowlogs_enable_logging
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestVPCFlowLogsEnableLogging:
    """Test cases for VPC Flow Logs enabled check."""

    def setup_method(self):
        """Set up mock session and client responses."""

        metadata = CheckMetadata(
            Provider="aws",
            CheckID="vpc_flowlogs_enable_logging",
            CheckTitle="Ensure VPC Flow Logs are enabled for all VPCs.",
            CheckType=["security", "monitoring"],
            ServiceName="ec2",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
            Severity="medium",
            ResourceType="AwsVpc",
            Risk="Without VPC Flow Logs enabled, there is no visibility into the network traffic.",
            RelatedUrl="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ec2 create-flow-logs --resource-type VPC --resource-id <vpc_id> --traffic-type ALL --log-group-name <log_group_name> --deliver-logs-permission-arn <role_arn>",
                    NativeIaC=None,
                    Terraform=None,
                    Other="https://aws.amazon.com/premiumsupport/knowledge-center/vpc-flow-logs-cloudwatch/"
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable VPC Flow Logs for all VPCs using the AWS Management Console or CLI.",
                    Url="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
                )
            ),
            Description="Ensure VPC Flow Logs are enabled for all VPCs to monitor network traffic.",
            Categories=["security", "monitoring"]
        )

        self.check = vpc_flowlogs_enable_logging(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_sts = MagicMock()

        self.mock_session.client.side_effect = (
            lambda service_name: self.mock_client if service_name == "ec2" else self.mock_sts
        )

        self.mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012"
        }

    def set_vpc_flow_logs(self, vpcs, flow_logs_side_effect):
        """Helper method to mock VPCs and corresponding flow logs."""
        self.mock_client.describe_vpcs.return_value = {"Vpcs": vpcs}
        self.mock_client.describe_flow_logs.side_effect = flow_logs_side_effect

    def test_all_vpcs_have_flow_logs_enabled(self):
        """Test when all VPCs have flow logs enabled."""
        self.set_vpc_flow_logs(
            [{"VpcId": "vpc-123"}, {"VpcId": "vpc-456"}],
            [{"FlowLogs": [{"FlowLogId": "fl-1"}]}, {"FlowLogs": [{"FlowLogId": "fl-2"}]}]
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 2
        assert all(r.status == CheckStatus.PASSED for r in report.resource_ids_status)

    def test_all_vpcs_have_flow_logs_disabled(self):
        """Test when all VPCs have flow logs disabled."""
        self.set_vpc_flow_logs(
            [{"VpcId": "vpc-111"}, {"VpcId": "vpc-222"}],
            [{"FlowLogs": []}, {"FlowLogs": []}]
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        assert all(r.status == CheckStatus.FAILED for r in report.resource_ids_status)

    def test_some_vpcs_have_flow_logs_disabled(self):
        """Test when some VPCs have flow logs disabled."""
        self.set_vpc_flow_logs(
            [{"VpcId": "vpc-abc"}, {"VpcId": "vpc-def"}],
            [{"FlowLogs": [{"FlowLogId": "fl-abc"}]}, {"FlowLogs": []}]
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        assert any(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)

    def test_no_vpcs_exist(self):
        """Test when no VPCs exist in the account."""
        self.mock_client.describe_vpcs.return_value = {"Vpcs": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No VPCs found" in report.resource_ids_status[0].summary

    def test_client_error_handling(self):
        """Test error handling when a ClientError occurs in describe_vpcs."""
        error_response = {'Error': {'Code': 'UnauthorizedOperation', 'Message': 'Access denied'}}
        self.mock_client.describe_vpcs.side_effect = ClientError(error_response, 'DescribeVpcs')

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error fetching VPCs" in report.resource_ids_status[0].summary

    def test_flow_logs_missing_key(self):
        """Test when 'FlowLogs' key is missing in describe_flow_logs response."""
        self.set_vpc_flow_logs(
            [{"VpcId": "vpc-999"}],
            [{}]  # Missing 'FlowLogs' key
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED or report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status in [CheckStatus.FAILED, CheckStatus.UNKNOWN]

    def test_flow_logs_api_failure(self):
        """Test ClientError from describe_flow_logs."""
        self.set_vpc_flow_logs(
            [{"VpcId": "vpc-fail"}],
            [ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'Denied'}}, 'DescribeFlowLogs')]
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "error" in report.resource_ids_status[0].summary.lower()
