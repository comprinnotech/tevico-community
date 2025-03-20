"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-13
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_authentication_failures(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        logs_client = connection.client("logs")
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            log_groups = []
            next_token = None

            while True:
                response = logs_client.describe_log_groups(nextToken=next_token) if next_token else logs_client.describe_log_groups()
                log_groups.extend(response.get("logGroups", []))
                next_token = response.get("nextToken")
                
                if not next_token:
                    break

            if not log_groups:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudWatch log groups found."
                    )
                )
                return report

            for log_group in log_groups:
                log_group_name = log_group["logGroupName"]
                log_group_arn = log_group['arn']
                
                try:
                    metric_filters = logs_client.describe_metric_filters(logGroupName=log_group_name)
                    filters = metric_filters.get("metricFilters", [])
                    
                    auth_failure_filter = any(
                        "authentication" in f["filterPattern"].lower() or "failed" in f["filterPattern"].lower()
                        for f in filters
                    )

                    if auth_failure_filter:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=log_group_arn),
                                status=CheckStatus.PASSED,
                                summary=f"CloudWatch log group {log_group_name} has a metric filter for authentication failures."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=log_group_arn),
                                status=CheckStatus.FAILED,
                                summary=f"CloudWatch log group {log_group_name} does NOT have a metric filter for authentication failures."
                            )
                        )
                except (BotoCoreError, ClientError) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=log_group_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking metric filters for log group {log_group_name}.",
                            exception=str(e)
                        )
                    )
        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving CloudWatch log groups.",
                    exception=str(e)
                )
            )

        return report

