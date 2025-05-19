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


class cloudwatch_log_metric_filter_authentication_failures(Check):
    
    def get_alarm_names(self, cloudwatch_client, metric_name, namespace):
        """Retrieve associated alarm names for a given metric name and namespace."""
        try:
            response = cloudwatch_client.describe_alarms_for_metric(
                MetricName=metric_name,
                Namespace=namespace
            )
            alarms = response.get("MetricAlarms", [])
            return [alarm["AlarmName"] for alarm in alarms]
        except Exception as e:
            return []

    def execute(self, connection: boto3.Session) -> CheckReport:
        logs_client = connection.client('logs')
        cloudwatch_client = connection.client('cloudwatch')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Define the authentication failures pattern
            pattern = re.compile(r"\$\.eventName\s*=\s*.?ConsoleLogin.+\$\.errorMessage\s*=\s*.?Failed authentication.?")
            
            # Fetch all metric filters with pagination
            metric_filters = []
            paginator = logs_client.get_paginator('describe_metric_filters')
            for page in paginator.paginate():
                metric_filters.extend(page.get('metricFilters', []))

            # Filter metric filters that match the authentication failures pattern
            filtered_metric_filters = [f for f in metric_filters if re.search(pattern, f.get("filterPattern", ""))]

            # If no matching metric filters are found, exit early
            if not filtered_metric_filters:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="No metric filters found matching the authentication failures pattern."
                    )
                )
                return report  # Early exit

            # Fetch all log groups dynamically with pagination (to get ARNs)
            log_groups = []
            paginator = logs_client.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                log_groups.extend(page.get('logGroups', []))
            
            log_group_arns = {lg["logGroupName"]: lg["arn"][0:-2] for lg in log_groups}

            # Iterate over log groups with authentication failures metric filters
            for metric_filter in filtered_metric_filters:
                log_group_name = metric_filter["logGroupName"]
                log_group_arn = log_group_arns.get(log_group_name, f"Unknown ARN for {log_group_name}")
                filter_name = metric_filter["filterName"]
                
                metric_transformations = metric_filter.get("metricTransformations", [])
                if not metric_transformations:
                    continue  # Skip if no metric transformation exists
                
                metric_name = metric_transformations[0].get("metricName")
                namespace = metric_transformations[0].get("metricNamespace")

                # Fetch associated alarm names
                alarm_names = self.get_alarm_names(cloudwatch_client, metric_name, namespace)

                if alarm_names:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=log_group_arn),
                            status=CheckStatus.PASSED,
                            summary=f"Log group {log_group_name} has metric filter '{filter_name}' for authentication failures and associated alarms: {', '.join(alarm_names)}."
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=log_group_arn),
                            status=CheckStatus.FAILED,
                            summary=f"Log group {log_group_name} has metric filter '{filter_name}' for authentication failures but no associated alarms."
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Encountered an error while retrieving CloudWatch data.",
                    exception=str(e)
                )
            )

        return report
