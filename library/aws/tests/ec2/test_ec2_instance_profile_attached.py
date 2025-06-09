"""
Test suite for the ec2_instance_profile_attached check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 09-06-2025
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import CheckStatus, GeneralResource, CheckMetadata, Remediation, RemediationRecommendation, RemediationCode
from library.aws.checks.ec2.ec2_instance_profile_attached import ec2_instance_profile_attached


class TestEc2InstanceProfileAttached:
    """
    Test suite for ec2_instance_profile_attached check.

    This check verifies whether running EC2 instances have IAM instance profiles attached.
    """

    def setup_method(self):
        """
        Setup before each test:
        - Instantiate the check class with required metadata.
        - Mock boto3 session and EC2 client.
        """

        metadata = CheckMetadata(
            Provider="AWS",
            CheckID="EC2-001",
            CheckTitle="EC2 Instance Profile Attached",
            CheckType=["Security"],
            ServiceName="EC2",
            SubServiceName="Instance Profile",
            ResourceIdTemplate="ec2-instance/{InstanceId}",
            Severity="HIGH",
            ResourceType="AWS::EC2::Instance",
            Risk="Instances without IAM instance profiles might lack required permissions.",
            Remediation = Remediation(
                Code = RemediationCode(),
                Recommendation = RemediationRecommendation(
                    Text="Attach an IAM instance profile to the EC2 instance.",
                    Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html"
                ),
            ),
            Description="Check that EC2 instances have IAM instance profiles attached.",
        )

        self.check = ec2_instance_profile_attached(metadata=metadata)
        self.mock_session = MagicMock()
        self.mock_ec2_client = MagicMock()
        self.mock_session.client.return_value = self.mock_ec2_client

    
    def test_no_instances(self):
        """
        When there are no running EC2 instances:
        - The check should mark status NOT_APPLICABLE.
        - The report should contain one resource status with empty name and appropriate summary.
        """
        self.mock_ec2_client.get_paginator.return_value.paginate.return_value = [
            {'Reservations': []}
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        rs = report.resource_ids_status[0]
        assert rs.status == CheckStatus.NOT_APPLICABLE
        assert rs.summary == "No running EC2 instances found."
        assert getattr(rs.resource, "name", "") == ""

    
    def test_instances_with_profiles(self):
        """
        When EC2 instances have IAM instance profiles attached:
        - The check should pass for those instances.
        - The summary should reflect the attached instance profile name.
        """
        instance_id = "i-1234567890abcdef0"
        profile_arn = "arn:aws:iam::123456789012:instance-profile/MyInstanceProfile"

        self.mock_ec2_client.get_paginator.return_value.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': instance_id,
                                'State': {'Name': 'running'},
                                'IamInstanceProfile': {'Arn': profile_arn}
                            }
                        ]
                    }
                ]
            }
        ]

        report = self.check.execute(self.mock_session)

        assert report.status is None
        assert len(report.resource_ids_status) == 1
        rs = report.resource_ids_status[0]
        assert rs.status == CheckStatus.PASSED
        assert getattr(rs.resource, "name", "") == instance_id
        assert "has an instance profile 'MyInstanceProfile' attached" in (rs.summary or "")

    
    def test_instances_without_profiles(self):
        """
        When EC2 instances do NOT have IAM instance profiles attached:
        - The check should fail for those instances.
        - The summary should indicate no instance profile attached.
        """
        instance_id = "i-0abcdef1234567890"

        self.mock_ec2_client.get_paginator.return_value.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': instance_id,
                                'State': {'Name': 'running'},
                                # No IamInstanceProfile key here
                            }
                        ]
                    }
                ]
            }
        ]

        report = self.check.execute(self.mock_session)

        assert report.status is None
        assert len(report.resource_ids_status) == 1
        rs = report.resource_ids_status[0]
        assert rs.status == CheckStatus.FAILED
        assert getattr(rs.resource, "name", "") == instance_id
        assert "does NOT have an instance profile attached" in (rs.summary or "")

    
    def test_mixed_instances(self):
        """
        When EC2 instances are mixed:
        - Running instances with profiles pass.
        - Running instances without profiles fail.
        - Instances in 'pending' or 'terminated' states are ignored.
        """
        instances = [
            {
                'InstanceId': "i-profiled",
                'State': {'Name': 'running'},
                'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/Profile1'}
            },
            {
                'InstanceId': "i-unprofiled",
                'State': {'Name': 'running'},
                # No instance profile attached
            },
            {
                'InstanceId': "i-pending",
                'State': {'Name': 'pending'},
                'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/ProfilePending'}
            },
            {
                'InstanceId': "i-terminated",
                'State': {'Name': 'terminated'},
                # Should be skipped
            }
        ]

        self.mock_ec2_client.get_paginator.return_value.paginate.return_value = [
            {'Reservations': [{'Instances': instances}]}
        ]

        report = self.check.execute(self.mock_session)

        assert len(report.resource_ids_status) == 2

        profiled = next(r for r in report.resource_ids_status if getattr(r.resource, "name", "") == "i-profiled")
        unprofiled = next(r for r in report.resource_ids_status if getattr(r.resource, "name", "") == "i-unprofiled")

        assert profiled.status == CheckStatus.PASSED
        assert "has an instance profile 'Profile1' attached" in (profiled.summary or "")

        assert unprofiled.status == CheckStatus.FAILED
        assert "does NOT have an instance profile attached" in (unprofiled.summary or "")

    
    def test_boto_core_error(self):
        """
        When boto3 raises a BotoCoreError:
        - The check status should be UNKNOWN.
        - The error should be reflected in the resource summary and exception.
        """
        self.mock_ec2_client.get_paginator.side_effect = BotoCoreError()

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        rs = report.resource_ids_status[0]
        assert rs.status == CheckStatus.UNKNOWN
        assert "Error retrieving EC2 instance profile information." in (rs.summary or "")
        assert rs.exception is not None

    
    def test_client_error(self):
        """
        When boto3 raises a ClientError:
        - The check status should be UNKNOWN.
        - The error should be reflected in the resource summary and exception.
        """
        error_response = {'Error': {'Code': 'SomeError', 'Message': 'An error occurred'}}
        self.mock_ec2_client.get_paginator.side_effect = ClientError(error_response, 'DescribeInstances')

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        rs = report.resource_ids_status[0]
        assert rs.status == CheckStatus.UNKNOWN
        assert "Error retrieving EC2 instance profile information." in (rs.summary or "")
        assert "An error occurred" in (rs.exception or "")