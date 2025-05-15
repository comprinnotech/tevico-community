"""
Test suite for the ec2_elastic_ips_unassociated check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-15
"""

import boto3
from botocore.stub import Stubber
from botocore.exceptions import BotoCoreError

from library.aws.checks.ec2.ec2_elastic_ips_unassociated import ec2_elastic_ips_unassociated
from tevico.engine.entities.report.check_model import (
    CheckMetadata, Remediation, RemediationCode, RemediationRecommendation,
    CheckStatus
)

# Helper to create CheckMetadata instance
def build_check_metadata(
    check_id="ec2_elastic_ips_unassociated",
    check_title="Elastic IPs should be associated",
    service_name="EC2"
) -> CheckMetadata:
    return CheckMetadata(
        Provider="aws",
        CheckID=check_id,
        CheckTitle=check_title,
        CheckType=["Security"],
        ServiceName=service_name,
        SubServiceName="Elastic IPs",
        ResourceIdTemplate="{AllocationId}",
        Severity="Medium",
        ResourceType="AWS::EC2::EIP",
        Risk="Unassociated EIPs may incur unnecessary cost.",
        RelatedUrl="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
        Remediation=Remediation(
            Code=RemediationCode(CLI="aws ec2 release-address --allocation-id <value>"),
            Recommendation=RemediationRecommendation(
                Text="Release unassociated EIPs to avoid charges.",
                Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html"
            )
        ),
        Description="This check identifies unassociated Elastic IPs."
    )

# Dummy boto3 session wrapper for mocking
class DummySession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        return self._client

# Test: Unassociated EIP
def test_check_with_mocked_unassociated_eips():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2)

    stubber.add_response("describe_addresses", {
        "Addresses": [
            {
                "PublicIp": "1.2.3.4",
                "AllocationId": "eipalloc-12345678"
            }
        ]
    })

    stubber.activate()

    check = ec2_elastic_ips_unassociated(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(ec2))

    assert report.status == CheckStatus.FAILED
    assert len(report.resource_ids_status) == 1
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "unassociated" in report.resource_ids_status[0].summary

# Test: No Elastic IPs
def test_check_with_no_eips():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2)

    stubber.add_response("describe_addresses", {"Addresses": []})
    stubber.activate()

    check = ec2_elastic_ips_unassociated(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(ec2))

    assert report.status == CheckStatus.NOT_APPLICABLE
    assert len(report.resource_ids_status) == 1
    assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE

# Test: All EIPs associated
def test_check_with_all_associated_eips():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2)

    stubber.add_response("describe_addresses", {
        "Addresses": [
            {
                "PublicIp": "5.6.7.8",
                "AllocationId": "eipalloc-87654321",
                "InstanceId": "i-0abcdef1234567890"
            }
        ]
    })

    stubber.activate()

    check = ec2_elastic_ips_unassociated(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(ec2))

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED

# Test: Mixed EIPs (some associated, some not)
def test_check_with_mixed_eips():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2)

    stubber.add_response("describe_addresses", {
        "Addresses": [
            {
                "PublicIp": "1.2.3.4",
                "AllocationId": "eipalloc-unassociated"
            },
            {
                "PublicIp": "5.6.7.8",
                "AllocationId": "eipalloc-associated",
                "InstanceId": "i-0abcdef1234567890"
            }
        ]
    })

    stubber.activate()

    check = ec2_elastic_ips_unassociated(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(ec2))

    assert report.status == CheckStatus.FAILED
    assert len(report.resource_ids_status) == 2
    assert any(r.status == CheckStatus.FAILED for r in report.resource_ids_status)
    assert any(r.status == CheckStatus.PASSED for r in report.resource_ids_status)

# Test: BotoCoreError exception
def test_check_with_boto_exception():
    class FailingSession:
        def client(self, service_name):
            raise BotoCoreError()

    check = ec2_elastic_ips_unassociated(metadata=build_check_metadata())
    report = check.execute(connection=FailingSession())

    assert report.status == CheckStatus.UNKNOWN
    assert len(report.resource_ids_status) == 1
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN

# Test: Missing fields in response
def test_check_with_missing_fields():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2)

    # Missing AllocationId and PublicIp
    stubber.add_response("describe_addresses", {
        "Addresses": [{}]
    })

    stubber.activate()

    check = ec2_elastic_ips_unassociated(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(ec2))

    assert report.status == CheckStatus.FAILED
    assert len(report.resource_ids_status) == 1
    assert "Unknown" in report.resource_ids_status[0].summary