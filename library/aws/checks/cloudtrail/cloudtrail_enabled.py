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



class cloudtrail_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("cloudtrail")
        report = CheckReport(name=__name__, status=CheckStatus.PASSED, resource_ids_status=[])

        try:
            # Call describe_trails ONCE (no pagination needed)
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

                trail_status = client.get_trail_status(Name=trail_name)  # Use Name, NOT ARN
                is_logging = trail_status.get("IsLogging", False)
        

                status = CheckStatus.PASSED if is_logging else CheckStatus.FAILED
                summary = (
                    f"CloudTrail '{trail_name}' is actively logging."
                    if is_logging
                    else f"CloudTrail '{trail_name}' is NOT actively logging."
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
