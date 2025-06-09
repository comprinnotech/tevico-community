"""
Test for SSM EC2 instance termination protection check.
"""
import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from library.aws.checks.ssm.ssm_ec2instance_automatic_protection_check import ssm_ec2instance_automatic_protection_check
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation
class TestSsmEc2InstanceAutomaticProtection:
    """Test cases for EC2 instances managed by SSM with termination protection check."""
    def setup_method(self):
        """Set up method for initializing the check and mocking boto3 clients."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="ssm_ec2instance_automatic_protection_check",
            CheckTitle="Ensure EC2 instances managed by SSM have termination protection enabled",
            CheckType=["security"],
            ServiceName="ssm",
            SubServiceName="ec2",
            ResourceIdTemplate="arn:aws:ec2:region:account-id:instance/<INSTANCE_ID>",
            Severity="medium",
            ResourceType="AwsEc2Instance",
            Description="Ensure EC2 instances managed by SSM have termination protection enabled to prevent accidental termination.",
            Risk="If termination protection is not enabled, EC2 instances can be accidentally terminated, leading to data loss or downtime.",
            RelatedUrl="https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-managed-instances.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ec2 modify-instance-attribute --instance-id i-1234567890abcdef0 --disable-api-termination",
                    Terraform='resource "aws_instance" "example" {\n  disable_api_termination = true\n}',
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable termination protection for EC2 instances managed by SSM.",
                    Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#using-termination-protection"
                )
            ),
            Categories=["security", "instance-management"]
        )
        self.check = ssm_ec2instance_automatic_protection_check(metadata)
        self.mock_session = MagicMock()
        self.mock_ec2 = MagicMock()
        self.mock_ssm = MagicMock()
        self.mock_session.client.side_effect = lambda service_name: {
            'ec2': self.mock_ec2,
            'ssm': self.mock_ssm
        }[service_name]
    def test_ssm_managed_with_termination_protection_enabled(self):
        """Test SSM-managed instance with termination protection enabled."""
        # Mock EC2 paginator response
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-123456", "State": {"Name": "running"}}]}]}
        ]
        # Mock termination protection enabled
        self.mock_ec2.describe_instance_attribute.return_value = {
            "DisableApiTermination": {"Value": True}
        }
        # Mock SSM-managed instance
        self.mock_ssm.get_paginator.return_value.paginate.return_value = [
            {"InstanceInformationList": [{"InstanceId": "i-123456"}]}
        ]
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "termination protection enabled" in report.resource_ids_status[0].summary
    def test_ssm_managed_with_termination_protection_disabled(self):
        """Test SSM-managed instance without termination protection."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-234567", "State": {"Name": "running"}}]}]}
        ]
        self.mock_ec2.describe_instance_attribute.return_value = {
            "DisableApiTermination": {"Value": False}
        }
        self.mock_ssm.get_paginator.return_value.paginate.return_value = [
            {"InstanceInformationList": [{"InstanceId": "i-234567"}]}
        ]
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does not have termination protection enabled" in report.resource_ids_status[0].summary
    def test_running_instances_none_managed_by_ssm(self):
        """Test running EC2 instances that are not managed by SSM."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-345678", "State": {"Name": "running"}}]}]}
        ]
        self.mock_ssm.get_paginator.return_value.paginate.return_value = [
            {"InstanceInformationList": []}
        ]
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert "No EC2 instances are managed by SSM" in report.resource_ids_status[0].summary
    def test_no_running_ec2_instances(self):
        """Test when there are no running EC2 instances."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-999999", "State": {"Name": "stopped"}}]}]}
        ]
        self.mock_ssm.get_paginator.return_value.paginate.return_value = [
            {"InstanceInformationList": []}
        ]
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert "No running EC2 instances found" in report.resource_ids_status[0].summary