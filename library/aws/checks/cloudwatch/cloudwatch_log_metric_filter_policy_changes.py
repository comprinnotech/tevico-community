"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-13
"""

import boto3
import re
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_policy_changes(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        logs_client = connection.client('logs')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            log_groups = []
            next_token = None

            while True:
                response = logs_client.describe_log_groups(nextToken=next_token) if next_token else logs_client.describe_log_groups()
                log_groups.extend(response.get('logGroups', []))
                next_token = response.get('nextToken')
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

            # Define the custom pattern for IAM policy changes (Put/Attach/Delete actions)
            policy_change_pattern = r"\$\.eventName\s*=\s*.?DeleteGroupPolicy.+\$\.eventName\s*=\s*.?DeleteRolePolicy.+\$\.eventName\s*=\s*.?DeleteUserPolicy.+\$\.eventName\s*=\s*.?PutGroupPolicy.+\$\.eventName\s*=\s*.?PutRolePolicy.+\$\.eventName\s*=\s*.?PutUserPolicy.+\$\.eventName\s*=\s*.?CreatePolicy.+\$\.eventName\s*=\s*.?DeletePolicy.+\$\.eventName\s*=\s*.?CreatePolicyVersion.+\$\.eventName\s*=\s*.?DeletePolicyVersion.+\$\.eventName\s*=\s*.?AttachRolePolicy.+\$\.eventName\s*=\s*.?DetachRolePolicy.+\$\.eventName\s*=\s*.?AttachUserPolicy.+\$\.eventName\s*=\s*.?DetachUserPolicy.+\$\.eventName\s*=\s*.?AttachGroupPolicy.+\$\.eventName\s*=\s*.?DetachGroupPolicy.?"
   
            for log_group in log_groups:
                log_group_name = log_group.get('logGroupName')
                log_group_arn = log_group.get('arn')[0:-2]
               

                try:
                    metric_filters = logs_client.describe_metric_filters(logGroupName=log_group_name).get('metricFilters', [])
                    matching_filters = [
                        filter.get('filterName') for filter in metric_filters if re.search(policy_change_pattern, filter.get("filterPattern", ""))
                    ]
                    
                    if matching_filters:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=log_group_arn),
                                status=CheckStatus.PASSED,
                                summary=f"Log group {log_group_name} has policy change metric filters: {', '.join(matching_filters)}."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=log_group_arn),
                                status=CheckStatus.FAILED,
                                summary=f"Log group {log_group_name} does not have policy change metric filters."
                            )
                        )
                except (BotoCoreError, ClientError) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=log_group_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving metric filters for log group {log_group_name}.",
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