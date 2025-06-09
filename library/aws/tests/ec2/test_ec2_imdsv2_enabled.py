"""
Test for EC2 IMDSv2 enforcement check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 09-06-2025
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.ec2.ec2_imdsv2_enabled import ec2_imdsv2_enabled
from tevico.engine.entities.report.check_model import (
    CheckStatus, CheckMetadata,
    Remediation, RemediationCode, RemediationRecommendation
)


class TestEc2Imdsv2Enabled:
    """Test cases for EC2 IMDSv2 enforcement check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="ec2_imdsv2_enabled",
            CheckTitle="EC2 Instances Require IMDSv2",
            CheckType=["security"],
            ServiceName="ec2",
            SubServiceName="metadata-service",
            ResourceIdTemplate="arn:aws:ec2:{region}::instance/{resource_id}",
            Severity="high",
            ResourceType="ec2",
            Risk="Instances not using IMDSv2 are vulnerable to SSRF attacks",
            RelatedUrl="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ec2 modify-instance-metadata-options --instance-id <value> --http-endpoint enabled --http-tokens required",
                    Terraform='resource "aws_instance" "example" {\n  metadata_options {\n    http_endpoint = "enabled"\n    http_tokens = "required"\n  }\n}',
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Ensure IMDSv2 is required and enabled for all EC2 instances",
                    Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
                )
            ),
            Description="Checks whether all EC2 instances enforce the use of IMDSv2.",
            Categories=["security", "compliance"]
        )

        self.check = ec2_imdsv2_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_imdsv2_fully_enabled(self):
        """Test when all instances have IMDSv2 fully enabled."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-1234567890abcdef0",
                                "State": {"Name": "running"},
                                "MetadataOptions": {
                                    "HttpTokens": "required",
                                    "HttpEndpoint": "enabled"
                                }
                            }
                        ]
                    }
                ]
            }
        ]

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED or all(res.status == CheckStatus.PASSED for res in report.resource_ids_status)
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "has IMDSv2 fully enabled" in (report.resource_ids_status[0].summary or "")

    def test_imdsv2_not_enforced(self):
        """Test when instance does not enforce IMDSv2."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-abcdef0123456789",
                                "State": {"Name": "running"},
                                "MetadataOptions": {
                                    "HttpTokens": "optional",
                                    "HttpEndpoint": "enabled"
                                }
                            }
                        ]
                    }
                ]
            }
        ]

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED or any(res.status == CheckStatus.FAILED for res in report.resource_ids_status)
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does NOT fully enforce IMDSv2" in (report.resource_ids_status[0].summary or "")

    def test_instance_missing_metadata_options(self):
        """Test instance with no MetadataOptions field."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-no-meta-options",
                                "State": {"Name": "running"}
                            }
                        ]
                    }
                ]
            }
        ]

        report = self.check.execute(self.mock_session)
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does NOT fully enforce IMDSv2" in (report.resource_ids_status[0].summary or "")

    def test_no_running_instances(self):
        """Test when there are no running EC2 instances."""
        self.mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Reservations": []
            }
        ]

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No running EC2 instances found" in (report.resource_ids_status[0].summary or "")

    def test_client_error(self):
        """Test ClientError is handled properly."""
        self.mock_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized"}}, "DescribeInstances"
        )

        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving EC2 metadata service configuration" in (report.resource_ids_status[0].summary or "")
