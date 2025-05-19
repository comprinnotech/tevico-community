'''
Author : Khushi Kalantri
EMAIL: khushi.kalantri@comprinno.net
DATE: 2025-05-16
'''
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check

class route53_health_checks_status(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        try:
            route53_client = connection.client('route53')

            # Fetch all health checks
            health_checks = []
            paginator = route53_client.get_paginator('list_health_checks')
            for page in paginator.paginate():
                health_checks.extend(page.get('HealthChecks', []))

            if not health_checks:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Route 53 health checks found."
                    )
                )
                return report

            # Collect associated health check IDs via failover routing policies
            associated_health_check_ids = set()
            hosted_zones = route53_client.list_hosted_zones().get("HostedZones", [])
            for zone in hosted_zones:
                zone_id = zone["Id"].split("/")[-1]
                record_sets_paginator = route53_client.get_paginator('list_resource_record_sets')
                for page in record_sets_paginator.paginate(HostedZoneId=zone_id):
                    for record in page.get("ResourceRecordSets", []):
                        if "HealthCheckId" in record:
                            associated_health_check_ids.add(record["HealthCheckId"])


            # Check each health check
            for hc in health_checks:
                hc_id = hc["Id"]
                hc_arn = f"arn:aws:route53:::healthcheck/{hc_id}"
                if hc_id in associated_health_check_ids:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=hc_arn),
                            status=CheckStatus.PASSED,
                            summary=f"Health check {hc_id} is associated with a failover routing policy."
                        )
                    )
                else:
                    report.status = CheckStatus.FAILED
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=hc_arn),
                            status=CheckStatus.FAILED,
                            summary=f"Health check {hc_id} is not associated with any failover routing policy."
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve Route 53 health check data.",
                    exception=str(e)
                )
            )
        return report
