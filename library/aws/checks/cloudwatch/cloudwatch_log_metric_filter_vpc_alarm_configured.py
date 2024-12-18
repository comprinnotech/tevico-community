"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_vpc_alarm_configured(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('cloudwatch')
        logs_client = connection.client('logs')

        report.resource_ids_status = {}  # Initialize resource_ids_status
        changes_detected = False

        try:
            response = logs_client.describe_metric_filters()
            metric_filters = response.get('metricFilters', [])

            if not metric_filters:
                report.resource_ids_status["NoMetricFilters"] = False  # Explicitly set status
                report.passed = False
                return report

            for metric_filter in metric_filters:
                try:
                    filter_name = metric_filter['filterName']
                    filter_pattern = metric_filter.get('filterPattern', '')

                    if "vpc" in filter_pattern.lower():
                        alarms_response = cloudwatch_client.describe_alarms_for_metric(
                            MetricName=filter_name,
                            Namespace="AWS/Logs",
                            Dimensions=[{'Name': 'LogGroupName', 'Value': 'VPC'}]
                        )

                        alarms = alarms_response.get('MetricAlarms', [])
                        report.resource_ids_status[filter_name] = bool(alarms)

                        if alarms:
                            changes_detected = True
                        else:
                            changes_detected = False

                except Exception:
                    report.resource_ids_status[filter_name] = False
                    changes_detected = True
                    continue

        except Exception:
            report.passed = False
            return report

        # Final check: if all resource status values are True, mark the check as passed
        report.passed = all(status for status in report.resource_ids_status.values())

        return report
