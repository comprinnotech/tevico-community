"""
Test suite for the ec2_ebs_snapshot_encrypted check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 04-06-2025
"""

import boto3
from botocore.stub import Stubber
from botocore.exceptions import BotoCoreError, ClientError
import pytest
from tevico.engine.entities.report.check_model import (
    CheckMetadata, CheckStatus, Remediation, RemediationCode, RemediationRecommendation
)
from library.aws.checks.ec2.ec2_ebs_snapshot_encrypted import ec2_ebs_snapshot_encrypted


def build_check_metadata():
    return CheckMetadata(
        Provider="aws",
        CheckID="ec2_ebs_snapshot_encrypted",
        CheckTitle="EBS Snapshots should be encrypted",
        CheckType=["Security"],
        ServiceName="EC2",
        SubServiceName="Snapshots",
        ResourceIdTemplate="{SnapshotId}",
        Severity="High",
        ResourceType="AWS::EC2::Snapshot",
        Risk="Unencrypted EBS snapshots can expose sensitive data if compromised.",
        RelatedUrl="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws ec2 copy-snapshot --source-region <region> --source-snapshot-id <snapshot-id> --encrypted --kms-key-id <key-id>"
            ),
            Recommendation=RemediationRecommendation(
                Text="Use encrypted EBS snapshots to protect data at rest.",
                Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
            )
        ),
        Description="Ensure that all Amazon EBS snapshots are encrypted to enhance data security."
    )


class DummySession:
    """Dummy boto3 session wrapper for injecting stubbed clients."""
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        return self._client


def test_no_snapshots():
    """Should return NOT_APPLICABLE when no snapshots exist."""
    client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_response("describe_snapshots", {"Snapshots": []})
    stubber.activate()

    check = ec2_ebs_snapshot_encrypted(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
    assert "No EBS snapshots found" in (report.resource_ids_status[0].summary or "")


def test_all_snapshots_encrypted():
    """Should return PASSED when all snapshots are encrypted."""
    client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_response("describe_snapshots", {
        "Snapshots": [
            {"SnapshotId": "snap-1234", "Encrypted": True}
        ]
    })
    stubber.activate()

    check = ec2_ebs_snapshot_encrypted(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.resource_ids_status[0].status == CheckStatus.PASSED
    assert "snap-1234 is encrypted" in (report.resource_ids_status[0].summary or "")


def test_some_snapshots_unencrypted():
    """Should return FAILED for unencrypted snapshots."""
    client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_response("describe_snapshots", {
        "Snapshots": [
            {"SnapshotId": "snap-1111", "Encrypted": False},
            {"SnapshotId": "snap-2222", "Encrypted": True}
        ]
    })
    stubber.activate()

    check = ec2_ebs_snapshot_encrypted(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    failed = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]
    passed = [r for r in report.resource_ids_status if r.status == CheckStatus.PASSED]

    assert len(failed) == 1
    assert failed[0].resource.name == "snap-1111" # type: ignore
    assert "NOT encrypted" in (failed[0].summary or "")
    assert len(passed) == 1
    assert passed[0].resource.name == "snap-2222" # type: ignore
    assert "is encrypted" in (passed[0].summary or "")


def test_snapshot_check_raises_exception():
    """Should return UNKNOWN if an exception occurs during snapshot fetch."""
    client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.activate()

    def raise_exception(*args, **kwargs):
        raise BotoCoreError()

    client.get_paginator = raise_exception  # type: ignore[assignment]

    check = ec2_ebs_snapshot_encrypted(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
    assert "Error retrieving" in (report.resource_ids_status[0].summary or "")
