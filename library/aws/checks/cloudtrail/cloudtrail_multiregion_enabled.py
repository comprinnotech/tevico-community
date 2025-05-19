"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-09
"""

import boto3
from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class cloudtrail_multiregion_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("cloudtrail")
        report = CheckReport(name=__name__, status=CheckStatus.PASSED, resource_ids_status=[])

        try:
            # Fetch all trails
            trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])

            if not trails:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudTrail trails found.",
                    )
                )
                return report  # Exit early if no trails exist

            for trail in trails:
                trail_name = trail["Name"]
                trail_arn = trail["TrailARN"]
                is_multi_region = trail.get("IsMultiRegionTrail", False)

                status = CheckStatus.PASSED if is_multi_region else CheckStatus.FAILED
                summary = (
                    f"CloudTrail '{trail_name}' is enabled for multiple regions."
                    if is_multi_region
                    else f"CloudTrail '{trail_name}' is NOT enabled for multiple regions."
                )

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(arn=trail_arn),
                        status=status,
                        summary=summary,
                    )
                )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving CloudTrail details.",
                    exception=str(e),
                )
            )

        return report
