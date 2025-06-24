import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.ssm.ssm_managed_compliant_patching import ssm_managed_compliant_patching
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestSsmManagedCompliantPatching:
    """Test cases for the SSM managed patch compliance check."""

    def setup_method(self):
        """Set up for each test."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="ssm_managed_compliant_patching",
            CheckTitle="Ensure SSM-managed EC2 instances are patch compliant",
            CheckType=["operations"],
            ServiceName="ssm",
            SubServiceName="patching",
            ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:instance/{resource_id}",
            Severity="medium",
            ResourceType="AwsEc2Instance",
            Risk="Non-compliant instances may be vulnerable due to missing critical patches",
            RelatedUrl="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-patch.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ssm describe-instance-patch-states --instance-ids <your-instance-id>",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable patch compliance scanning and ensure instances are patched",
                    Url="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-patch-compliance.html"
                )
            ),
            Description="Checks if SSM managed EC2 instances are compliant with patching requirements",
            Categories=["operations", "patching"]
        )

        self.check = ssm_managed_compliant_patching(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

        # Mock describe_instances to return a running instance
        self.mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "State": {"Name": "running"},
                            "Tags": [{"Key": "Name", "Value": "TestInstance"}]
                        }
                    ]
                }
            ]
        }

    def test_compliant_instance(self):
        """Test when an SSM managed EC2 instance is patch compliant."""
        self.mock_client.describe_instance_patch_states.return_value = {
            'InstancePatchStates': [
                {
                    'InstanceId': 'i-0123456789abcdef0',
                    'PatchSummary': {
                        'ComplianceType': 'Patch',
                        'CompliantCriticalCount': 5,
                        'NonCompliantCriticalCount': 0
                    }
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "compliant with patching" in report.resource_ids_status[0].summary.lower()

    def test_non_compliant_instance(self):
        """Test when an SSM managed EC2 instance is not patch compliant."""
        self.mock_client.describe_instance_patch_states.return_value = {
            'InstancePatchStates': [
                {
                    'InstanceId': 'i-0123456789abcdef0',
                    'PatchSummary': {
                        'ComplianceType': 'Patch',
                        'CompliantCriticalCount': 3,
                        'NonCompliantCriticalCount': 2
                    }
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "non-compliant with patching" in report.resource_ids_status[0].summary.lower()

    def test_client_error(self):
        """Test when SSM client throws an error (e.g., permissions or service failure)."""
        self.mock_client.describe_instance_patch_states.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation."}},
            "DescribeInstancePatchStates"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "error occurred" in report.resource_ids_status[0].summary.lower()
