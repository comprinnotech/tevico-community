"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""


import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class cloudwatch_log_metric_filter_vpc_alarm_configured(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('cloudwatch')
        logs_client = connection.client('logs')

        response = logs_client.describe_metric_filters()

        filters = response.get('metricFilters', [])
        if not filters:
            report.status = ResourceStatus.FAILED
            return report

        for metric_filter in filters:
            filter_name = metric_filter.get('FilterName')
            filter_pattern = metric_filter.get('FilterPattern')

            if filter_pattern is not None and "vpc" in filter_pattern.lower():

                alarms = cloudwatch_client.describe_alarms_for_metric(
                    MetricName=filter_name,
                    Namespace="AWS/Logs",
                    Dimensions=[{'Name': 'LogGroupName', 'Value': 'VPC'}]
                )

                if alarms['MetricAlarms']:
                    report.resource_ids_status[filter_name] = True
                else:
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[filter_name] = False

        return report
