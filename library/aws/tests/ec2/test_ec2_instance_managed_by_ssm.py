import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError, BotoCoreError
from typing import cast

from library.aws.checks.ec2.ec2_instance_managed_by_ssm import ec2_instance_managed_by_ssm
from tevico.engine.entities.report.check_model import (
    Remediation, RemediationCode, RemediationRecommendation
)
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, GeneralResource


class TestEc2InstanceManagedBySSM:
    """Test cases for EC2 instance managed by SSM check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="iam_password_policy_lowercase",
            CheckTitle="IAM Password Policy Requires Lowercase Characters",
            CheckType=["security"],
            ServiceName="iam",
            SubServiceName="password-policy",
            ResourceIdTemplate="arn:aws:iam::{account_id}:password-policy",
            Severity="medium",
            ResourceType="iam-password-policy",
            Risk="Passwords without lowercase characters are easier to guess",
            RelatedUrl="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws iam update-account-password-policy --require-lowercase-characters",
                    Terraform=(
                        'resource "aws_iam_account_password_policy" "strict" {\n'
                        '  require_lowercase_characters = true\n}'
                    ),
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Configure IAM password policy to require at least one lowercase letter",
                    Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                )
            ),
            Description="Checks if the IAM password policy requires at least one lowercase letter",
            Categories=["security", "compliance"]
        )

        self.check = ec2_instance_managed_by_ssm(metadata)
        self.mock_session = MagicMock()
        self.mock_ec2 = MagicMock()
        self.mock_ssm = MagicMock()

        self.mock_session.client.side_effect = lambda service: {
            "ec2": self.mock_ec2,
            "ssm": self.mock_ssm
        }[service]

    def test_no_instances(self):
        """Test when no EC2 instances are present."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No running EC2 instances found." in (report.resource_ids_status[0].summary or "")

    def test_all_instances_managed_by_ssm(self):
        """Test when all EC2 instances are managed by SSM."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": [
                    {"Instances": [{"InstanceId": "i-1234567890abcdef0", "State": {"Name": "running"}}]}
                ]
            }
        ]
        self.mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"InstanceId": "i-1234567890abcdef0"}]
        }

        report = self.check.execute(self.mock_session)

        assert report.status is None
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "is managed by SSM" in  (report.resource_ids_status[0].summary or "")

    def test_some_instances_not_managed_by_ssm(self):
        """Test when some EC2 instances are not managed by SSM."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {"InstanceId": "i-1", "State": {"Name": "running"}},
                            {"InstanceId": "i-2", "State": {"Name": "running"}}
                        ]
                    }
                ]
            }
        ]
        self.mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"InstanceId": "i-2"}]
        }

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 2
        status_map = {cast(GeneralResource, r.resource).name: r.status for r in report.resource_ids_status}
        assert status_map["i-1"] == CheckStatus.FAILED
        assert status_map["i-2"] == CheckStatus.PASSED

    def test_all_instances_unmanaged(self):
        """Test when none of the EC2 instances are managed by SSM."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {"InstanceId": "i-1", "State": {"Name": "running"}}
                        ]
                    }
                ]
            }
        ]
        self.mock_ssm.describe_instance_information.return_value = {"InstanceInformationList": []}

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "NOT managed by SSM" in (report.resource_ids_status[0].summary or "")

    def test_instance_in_pending_or_terminated_state(self):
        """Test when instances are in a non-running state."""
        self.mock_ec2.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-x", "State": {"Name": "terminated"}}]}]}
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert "No running EC2 instances found." in (report.resource_ids_status[0].summary or "")

    def test_client_error(self):
        """Test when boto3 raises a ClientError."""
        self.mock_ec2.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AuthFailure", "Message": "Unauthorized"}}, "DescribeInstances"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving EC2 SSM management status" in (report.resource_ids_status[0].summary or "")

    def test_boto_core_error(self):
        """Test when boto3 raises a BotoCoreError."""
        from botocore.exceptions import EndpointConnectionError
        self.mock_ec2.get_paginator.side_effect = EndpointConnectionError(endpoint_url="https://ec2.amazonaws.com")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN