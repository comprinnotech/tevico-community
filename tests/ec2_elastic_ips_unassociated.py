from botocore.stub import Stubber
import boto3
from library.aws.checks.ec2.ec2_elastic_ips_unassociated import ec2_elastic_ips_unassociated
from tevico.engine.entities.report.check_model import CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
from tevico.engine.entities.report.check_model import CheckStatus

# Helper to create CheckMetadata
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

def test_check_with_mocked_eips():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2)

    stubber.add_response(
        "describe_addresses",
        {
            "Addresses": [
                {
                    "PublicIp": "1.2.3.4",
                    "AllocationId": "eipalloc-12345678"
                    # No InstanceId or NetworkInterfaceId
                }
            ]
        }
    )

    stubber.activate()

    # Use correct metadata
    dummy_metadata = build_check_metadata()

    # Patch connection.client to return our stubbed ec2 client
    class DummySession:
        def client(self, service_name):
            return ec2

    check = ec2_elastic_ips_unassociated(metadata=dummy_metadata)
    report = check.execute(connection=DummySession())

    assert report.status == CheckStatus.FAILED
    assert len(report.resource_ids_status) == 1
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "unassociated" in report.resource_ids_status[0].summary