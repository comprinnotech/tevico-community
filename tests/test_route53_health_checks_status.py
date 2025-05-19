"""
Test suite for the route53_health_checks_status check (first 4 test cases).
AUTHOR: Khushi Kalantri
EMAIL: khushi.kalantri@comprinno.net
DATE: 2025-05-19
"""

import boto3
from botocore.stub import Stubber
from botocore.exceptions import BotoCoreError
from library.aws.checks.route53.route53_health_checks_status import route53_health_checks_status
from tevico.engine.entities.report.check_model import (
    CheckMetadata, Remediation, RemediationCode, RemediationRecommendation, CheckStatus
)

def build_check_metadata() -> CheckMetadata:
    return CheckMetadata(
        Provider="aws",
        CheckID="route53_health_checks_status",
        CheckTitle="Route 53 health checks should be associated with DNS records or failover routing policies",
        CheckType=["Availability", "CostOptimization"],
        ServiceName="Route 53",
        SubServiceName="Health Checks",
        ResourceIdTemplate="{Id}",
        Severity="Medium",
        ResourceType="AWS::Route53::HealthCheck",
        Risk="Unassociated health checks increase costs and do not aid availability.",
        RelatedUrl="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html",
        Remediation=Remediation(
            Code=RemediationCode(CLI="aws route53 delete-health-check --health-check-id <value>"),
            Recommendation=RemediationRecommendation(
                Text="Ensure health checks are tied to DNS records or failover policies.",
                Url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html"
            )
        ),
        Description="This check identifies Route 53 health checks not associated with DNS records or failover routing."
    )

class DummySession(boto3.Session):
    def __init__(self, client):
        super().__init__()
        self._client = client

    def client(self, service_name, *args, **kwargs):
        return self._client

def set_overall_report_status(report):
    statuses = [r.status for r in report.resource_ids_status]
    if any(s == CheckStatus.FAILED for s in statuses):
        report.status = CheckStatus.FAILED
    elif any(s == CheckStatus.UNKNOWN for s in statuses):
        report.status = CheckStatus.UNKNOWN
    elif all(s == CheckStatus.PASSED for s in statuses):
        report.status = CheckStatus.PASSED
    elif all(s == CheckStatus.NOT_APPLICABLE for s in statuses):
        report.status = CheckStatus.NOT_APPLICABLE
    else:
        report.status = CheckStatus.UNKNOWN

def test_no_health_checks():
    r53 = boto3.client("route53", region_name="us-east-1")
    with Stubber(r53) as stubber:
        stubber.add_response("list_health_checks", {
            "HealthChecks": [],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        check = route53_health_checks_status(metadata=build_check_metadata())
        report = check.execute(connection=DummySession(r53))
        set_overall_report_status(report)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE

def test_health_check_associated_with_failover():
    """Test case 2: Health check associated with DNS record using failover routing."""
    r53 = boto3.client("route53", region_name="us-east-1")
    with Stubber(r53) as stubber:
        # Health checks
        stubber.add_response("list_health_checks", {
            "HealthChecks": [{
                "Id": "hc-1234",
                "HealthCheckVersion": 1,
                "CallerReference": "test-ref",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.1",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3
                }
            }],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        # Hosted zones
        stubber.add_response("list_hosted_zones", {
            "HostedZones": [{
                "Id": "/hostedzone/Z1D633PJN98FT9",
                "Name": "example.com.",
                "CallerReference": "caller-ref-1",
                "Config": {"PrivateZone": False},
                "ResourceRecordSetCount": 1
            }],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        # Resource record sets with failover and health check ID
        stubber.add_response("list_resource_record_sets", {
            "ResourceRecordSets": [{
                "Name": "example.com.",
                "Type": "A",
                "SetIdentifier": "failover-a",
                "Failover": "PRIMARY",
                "HealthCheckId": "hc-1234",
                "TTL": 60,
                "ResourceRecords": [{"Value": "192.0.2.1"}]
            }],
            "IsTruncated": False,
            "MaxItems": "100"
        }, {"HostedZoneId": "Z1D633PJN98FT9"})

        check = route53_health_checks_status(metadata=build_check_metadata())
        report = check.execute(connection=DummySession(r53))
        set_overall_report_status(report)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED

def test_health_check_associated_without_failover():
    """Test case 3: Health check associated with DNS record without failover routing."""
    r53 = boto3.client("route53", region_name="us-east-1")
    with Stubber(r53) as stubber:
        stubber.add_response("list_health_checks", {
            "HealthChecks": [{
                "Id": "hc-2345",
                "HealthCheckVersion": 1,
                "CallerReference": "test-ref",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.3",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3
                }
            }],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        stubber.add_response("list_hosted_zones", {
            "HostedZones": [{
                "Id": "/hostedzone/Z1D633PJN98FT9",
                "Name": "example.com.",
                "CallerReference": "caller-ref-3",
                "Config": {"PrivateZone": False},
                "ResourceRecordSetCount": 1
            }],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        # Resource record set with HealthCheckId but no failover
        stubber.add_response("list_resource_record_sets", {
            "ResourceRecordSets": [{
                "Name": "example.com.",
                "Type": "A",
                "HealthCheckId": "hc-2345",
                "TTL": 60,
                "ResourceRecords": [{"Value": "192.0.2.3"}]
            }],
            "IsTruncated": False,
            "MaxItems": "100"
        }, {"HostedZoneId": "Z1D633PJN98FT9"})

        check = route53_health_checks_status(metadata=build_check_metadata())
        report = check.execute(connection=DummySession(r53))
        set_overall_report_status(report)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED

def test_health_check_unassociated():
    """Test case 4: Health check exists but is not associated with any DNS record or failover."""
    r53 = boto3.client("route53", region_name="us-east-1")
    with Stubber(r53) as stubber:
        stubber.add_response("list_health_checks", {
            "HealthChecks": [{
                "Id": "hc-5678",
                "HealthCheckVersion": 1,
                "CallerReference": "test-ref",
                "HealthCheckConfig": {
                    "IPAddress": "192.0.2.2",
                    "Port": 80,
                    "Type": "HTTP",
                    "ResourcePath": "/",
                    "RequestInterval": 30,
                    "FailureThreshold": 3
                }
            }],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        stubber.add_response("list_hosted_zones", {
            "HostedZones": [{
                "Id": "/hostedzone/Z1D633PJN98FT9",
                "Name": "example.com.",
                "CallerReference": "caller-ref-2",
                "Config": {"PrivateZone": False},
                "ResourceRecordSetCount": 1
            }],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100"
        })

        # Resource record sets without HealthCheckId
        stubber.add_response("list_resource_record_sets", {
            "ResourceRecordSets": [{
                "Name": "example.com.",
                "Type": "A",
                "TTL": 60,
                "ResourceRecords": [{"Value": "192.0.2.2"}]
            }],
            "IsTruncated": False,
            "MaxItems": "100"
        }, {"HostedZoneId": "Z1D633PJN98FT9"})

        check = route53_health_checks_status(metadata=build_check_metadata())
        report = check.execute(connection=DummySession(r53))
        set_overall_report_status(report)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
