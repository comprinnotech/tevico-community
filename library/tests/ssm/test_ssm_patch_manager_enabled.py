import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.ssm.ssm_patch_manager_enabled import ssm_patch_manager_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestSsmPatchManagerEnabled:
    """Test cases for SSM Patch Manager enabled check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="ssm_patch_manager_enabled",
            CheckTitle="Ensure SSM Patch Manager is enabled on all managed instances",
            CheckType=["patch-management"],
            ServiceName="ssm",
            SubServiceName="",
            ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
            Severity="medium",
            ResourceType="AwsEc2Instance",
            Risk="Instances without SSM Patch Manager enabled may not have automated patching.",
            RelatedUrl="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-patch-patchgroup.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ssm register-managed-instance --instance-id <INSTANCE_ID>",
                    Terraform="https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_patch_baseline",
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable AWS Systems Manager Patch Manager for automated patching and compliance checks.",
                    Url="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-patch-patchgroup.html"
                )
            ),
            Description="Ensure that AWS Systems Manager Patch Manager is enabled on all managed instances.",
            Categories=["patch-management"]
        )

        self.check = ssm_patch_manager_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_ec2 = MagicMock()
        self.mock_ssm = MagicMock()

        self.mock_session.client.side_effect = lambda service: {
            "ec2": self.mock_ec2,
            "ssm": self.mock_ssm
        }[service]

    def test_no_running_instances(self):
        """Test when there are EC2 instances but none are running."""
        paginator_mock = MagicMock()
        self.mock_ec2.get_paginator.return_value = paginator_mock
        paginator_mock.paginate.return_value = [{
            "Reservations": [
                {"Instances": [{"InstanceId": "i-123", "State": {"Name": "stopped"}, "Tags": []}]}
            ]
        }]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No running EC2 instances found." in report.resource_ids_status[0].summary

    def test_instance_not_managed_by_ssm(self):
        """Test when running instance is not SSM-managed."""
        paginator_mock = MagicMock()
        self.mock_ec2.get_paginator.return_value = paginator_mock
        paginator_mock.paginate.return_value = [{
            "Reservations": [
                {"Instances": [{"InstanceId": "i-123", "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "TestInstance"}]}]}
            ]
        }]
        self.mock_ssm.describe_instance_information.return_value = {"InstanceInformationList": []}

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "is not managed by SSM" in report.resource_ids_status[0].summary

    def test_ssm_managed_but_patch_manager_not_enabled(self):
        """Test when instance is SSM-managed but no patch state is returned."""
        paginator_mock = MagicMock()
        self.mock_ec2.get_paginator.return_value = paginator_mock
        paginator_mock.paginate.return_value = [{
            "Reservations": [
                {"Instances": [{"InstanceId": "i-123", "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "TestInstance"}]}]}
            ]
        }]
        self.mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"InstanceId": "i-123"}]
        }
        self.mock_ssm.describe_instance_patch_states.return_value = {"InstancePatchStates": []}

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Patch Manager is not enabled" in report.resource_ids_status[0].summary

    def test_patch_manager_enabled(self):
        """Test when SSM-managed instance has Patch Manager enabled."""
        paginator_mock = MagicMock()
        self.mock_ec2.get_paginator.return_value = paginator_mock
        paginator_mock.paginate.return_value = [{
            "Reservations": [
                {"Instances": [{"InstanceId": "i-123", "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "TestInstance"}]}]}
            ]
        }]
        self.mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"InstanceId": "i-123"}]
        }
        self.mock_ssm.describe_instance_patch_states.return_value = {
            "InstancePatchStates": [{"InstanceId": "i-123", "PatchGroup": "default", "BaselineId": "pb-xyz"}]
        }

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "has Patch Manager enabled" in report.resource_ids_status[0].summary