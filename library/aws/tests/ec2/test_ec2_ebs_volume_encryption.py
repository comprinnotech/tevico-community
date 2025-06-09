"""
Test suite for the ec2_ebs_volume_encryption check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 04-06-2025
"""

import boto3
from botocore.stub import Stubber
from botocore.exceptions import BotoCoreError

from tevico.engine.entities.report.check_model import (
    CheckMetadata, CheckStatus, Remediation, RemediationCode, RemediationRecommendation
)
from library.aws.checks.ec2.ec2_ebs_volume_encryption import ec2_ebs_volume_encryption


class TestEc2EbsVolumeEncryption:
    """Test cases for the ec2_ebs_volume_encryption check."""

    def setup_method(self):
        """Set up common metadata and check instance for each test."""
        self.metadata = CheckMetadata(
            Provider="aws",
            CheckID="ec2_ebs_volume_encryption",
            CheckTitle="EBS Volumes should be encrypted",
            CheckType=["Security"],
            ServiceName="EC2",
            SubServiceName="Volumes",
            ResourceIdTemplate="{VolumeId}",
            Severity="High",
            ResourceType="AWS::EC2::Volume",
            Risk="Unencrypted EBS volumes may expose sensitive data if compromised.",
            RelatedUrl="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ec2 create-volume --encrypted --kms-key-id <your-kms-key-id> ..."
                ),
                Recommendation=RemediationRecommendation(
                    Text="Ensure all EBS volumes are encrypted using customer-managed or AWS-managed keys.",
                    Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
                )
            ),
            Description="This check ensures that all EBS volumes are encrypted for data-at-rest protection."
        )

    class DummySession:
        """Dummy boto3 session wrapper to inject mocked clients."""
        def __init__(self, client):
            self._client = client

        def client(self, service_name):
            return self._client

    def test_no_volumes(self):
        """Should return NOT_APPLICABLE when no EBS volumes are present."""
        client = boto3.client("ec2", region_name="us-east-1")
        stubber = Stubber(client)
        stubber.add_response("describe_volumes", {"Volumes": []})
        stubber.activate()

        check = ec2_ebs_volume_encryption(metadata=self.metadata)
        report = check.execute(connection=self.DummySession(client))  # type: ignore[arg-type]

        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert "No EBS volumes found" in (report.resource_ids_status[0].summary or "")

    def test_all_volumes_encrypted(self):
        """Should return PASSED when all EBS volumes are encrypted."""
        client = boto3.client("ec2", region_name="us-east-1")
        stubber = Stubber(client)
        stubber.add_response("describe_volumes", {
            "Volumes": [
                {"VolumeId": "vol-1234", "Encrypted": True},
                {"VolumeId": "vol-5678", "Encrypted": True}
            ]
        })
        stubber.activate()

        check = ec2_ebs_volume_encryption(metadata=self.metadata)
        report = check.execute(connection=self.DummySession(client))  # type: ignore[arg-type]

        for r in report.resource_ids_status:
            assert r.status == CheckStatus.PASSED
            assert "is encrypted" in (r.summary or "")

    def test_some_volumes_unencrypted(self):
        """Should return FAILED for unencrypted EBS volumes."""
        client = boto3.client("ec2", region_name="us-east-1")
        stubber = Stubber(client)
        stubber.add_response("describe_volumes", {
            "Volumes": [
                {"VolumeId": "vol-1", "Encrypted": True},
                {"VolumeId": "vol-2", "Encrypted": False}
            ]
        })
        stubber.activate()

        check = ec2_ebs_volume_encryption(metadata=self.metadata)
        report = check.execute(connection=self.DummySession(client))  # type: ignore[arg-type]

        statuses = {r.resource.name: r.status for r in report.resource_ids_status}  # type: ignore
        assert statuses["vol-1"] == CheckStatus.PASSED
        assert statuses["vol-2"] == CheckStatus.FAILED

    def test_volume_check_raises_exception(self):
        """Should return UNKNOWN if an error occurs while fetching volumes."""
        client = boto3.client("ec2", region_name="us-east-1")
        stubber = Stubber(client)
        stubber.activate()

        def raise_exception(*args, **kwargs):
            raise BotoCoreError()

        client.get_paginator = raise_exception  # type: ignore[assignment]

        check = ec2_ebs_volume_encryption(metadata=self.metadata)
        report = check.execute(connection=self.DummySession(client))  # type: ignore[arg-type]

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving" in (report.resource_ids_status[0].summary or "")
