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


class cloudtrail_cloudwatch_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudtrail')
        report = CheckReport(name=__name__, status=CheckStatus.PASSED, resource_ids_status=[])

        try:
            trails = []
            next_token = None

            while True:
                response = client.describe_trails(includeShadowTrails=False, NextToken=next_token) if next_token else client.describe_trails(includeShadowTrails=False)
                trails.extend(response.get('trailList', []))
                next_token = response.get('NextToken')
                
                if not next_token:
                    break

            if not trails:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudTrail trails found."
                    )
                )
                return report  # Early exit since there are no trails to check

            for trail in trails:
                trail_name = trail['Name']
                trail_arn = trail['TrailARN']
                cloudwatch_logs_role_arn = trail.get('CloudWatchLogsRoleArn', '')
                log_group_arn = trail.get('CloudWatchLogsLogGroupArn', '')
                is_logging_enabled = bool(cloudwatch_logs_role_arn and log_group_arn)
                
                status = CheckStatus.PASSED if is_logging_enabled else CheckStatus.FAILED
                summary = (
                    f"CloudTrail '{trail_name}' is logging to CloudWatch (Log Group ARN: {log_group_arn})."
                    if is_logging_enabled else
                    f"CloudTrail '{trail_name}' is NOT logging to CloudWatch."
                )
                
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(arn=trail_arn),
                        status=status,
                        summary=summary
                    )
                )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving CloudTrail details.",
                    exception=str(e)
                )
            )

        return report