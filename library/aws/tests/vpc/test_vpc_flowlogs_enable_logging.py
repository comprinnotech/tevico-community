import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from library.aws.checks.vpc.vpc_flowlogs_enable_logging import vpc_flowlogs_enable_logging
from tevico.engine.entities.report.check_model import CheckStatus


class TestVPCFlowLogsEnableLogging:
    """Test cases for VPC Flow Logs enabled check."""

    def setup_method(self):
        """Set up mock session and client responses."""
        self.check = vpc_flowlogs_enable_logging(metadata={})
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_sts = MagicMock()

        # Return appropriate mock client depending on service
        self.mock_session.client.side_effect = (
            lambda service_name: self.mock_client if service_name == "ec2" else self.mock_sts
        )

        self.mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012"
        }

    def test_all_vpcs_have_flow_logs_enabled(self):
        """Test when all VPCs have flow logs enabled."""
        self.mock_client.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-123"}, {"VpcId": "vpc-456"}]
        }
        self.mock_client.describe_flow_logs.side_effect = [
            {"FlowLogs": [{"FlowLogId": "fl-1"}]},
            {"FlowLogs": [{"FlowLogId": "fl-2"}]}
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert all(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert all("has Flow Logs enabled" in r.summary for r in report.resource_ids_status)
        assert len(report.resource_ids_status) == 2

    def test_all_vpcs_have_flow_logs_disabled(self):
        """Test when all VPCs have flow logs disabled."""
        self.mock_client.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-111"}, {"VpcId": "vpc-222"}]
        }
        self.mock_client.describe_flow_logs.side_effect = [
            {"FlowLogs": []},
            {"FlowLogs": []}
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert all(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        assert all("does not have Flow Logs enabled" in r.summary for r in report.resource_ids_status)
        assert len(report.resource_ids_status) == 2

    def test_some_vpcs_have_flow_logs_disabled(self):
        """Test when some VPCs have flow logs disabled."""
        self.mock_client.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-abc"}, {"VpcId": "vpc-def"}]
        }
        self.mock_client.describe_flow_logs.side_effect = [
            {"FlowLogs": [{"FlowLogId": "fl-abc"}]},
            {"FlowLogs": []}
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert any(r.status == CheckStatus.PASSED for r in report.resource_ids_status)
        assert any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
        assert any("has Flow Logs enabled" in r.summary for r in report.resource_ids_status)
        assert any("does not have Flow Logs enabled" in r.summary for r in report.resource_ids_status)
        assert len(report.resource_ids_status) == 2

    def test_no_vpcs_exist(self):
        """Test when no VPCs exist in the account."""
        self.mock_client.describe_vpcs.return_value = {"Vpcs": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No VPCs found" in report.resource_ids_status[0].summary

    def test_describe_vpcs_client_error(self):
        """Test handling of ClientError in describe_vpcs call."""
        self.mock_client.describe_vpcs.side_effect = ClientError(
            error_response={
                "Error": {
                    "Code": "UnauthorizedOperation",
                    "Message": "You are not authorized to perform this operation."
                }
            },
            operation_name="DescribeVpcs"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        result = report.resource_ids_status[0]
        assert result.status == CheckStatus.UNKNOWN
        assert "Error fetching VPCs" in result.summary
        assert "UnauthorizedOperation" in result.summary
        assert hasattr(result, "exception")
        assert "You are not authorized" in result.exception

    def test_flow_logs_describe_failure_for_one_vpc(self):
        """Test handling of exception in describe_flow_logs call."""
        self.mock_client.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-789"}]
        }

        self.mock_client.describe_flow_logs.side_effect = ClientError(
            error_response={
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Access denied to describe FlowLogs."
                }
            },
            operation_name="DescribeFlowLogs"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        result = report.resource_ids_status[0]
        assert result.status == CheckStatus.UNKNOWN
        assert "Access denied" in result.summary
        assert "vpc-789" in result.resource.arn  
        assert hasattr(result, "exception")
        assert "Access denied to describe FlowLogs" in result.exception
