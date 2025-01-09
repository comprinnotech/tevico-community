"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudwatch_log_metric_filter_vpc_alarm_configured(Check):
    def _get_metric_filters(self, client):
        try:
            # Fetch the list of metric filters from CloudWatch Logs
            response = client.describe_metric_filters()
            return response.get('metricFilters', [])
        except (ClientError, BotoCoreError):
            # Return an empty list in case of errors
            return []

    def _get_alarms_for_metric(self, client, metric_name, metric_namespace):
        try:
            # Fetch the alarms associated with a specific metric filter in CloudWatch
            response = client.describe_alarms_for_metric(
                MetricName=metric_name,
                Namespace=metric_namespace
            )
            return response.get('MetricAlarms', [])
        except (ClientError, BotoCoreError):
            # Return an empty list if there is an error retrieving alarms
            return []

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        cloudwatch_client = connection.client('cloudwatch')
        logs_client = connection.client('logs')

        # Initialize resource_ids_status dictionary to store results
        report.resource_ids_status = {}

        # Define VPC-related patterns to check
        vpc_patterns = [
            'vpc',
            'createvpc',
            'deletevpc',
            'modifyvpcattribute',
            'acceptvpcpeeringconnection',
            'deletevpcpeeringconnection',
            'rejectvpcpeeringconnection',
            'createvpcendpoint',
            'deletevpcendpoints',
            'modifyvpcendpoint'
        ]

        try:
            # Retrieve metric filters from CloudWatch logs
            metric_filters = self._get_metric_filters(logs_client)

            if not metric_filters:
                # If no metric filters are found, mark the report as failed and return
                report.passed = False
                report.resource_ids_status["NoMetricFilters"] = False
                return report

            vpc_filters_found = False

            # Iterate through each metric filter to check if it matches VPC patterns
            for filter in metric_filters:
                try:
                    filter_name = filter['filterName']
                    filter_pattern = filter.get('filterPattern', '')

                    # Check if the filter's pattern contains VPC-related terms
                    if any(pattern in filter_pattern.lower() for pattern in vpc_patterns):
                        vpc_filters_found = True
                        
                        # Check metric transformations
                        for transformation in filter.get('metricTransformations', []):
                            metric_name = transformation.get('metricName')
                            metric_namespace = transformation.get('metricNamespace')

                            if not metric_name or not metric_namespace:
                                continue

                            # If a matching filter is found, check if there are any alarms for it
                            alarms = self._get_alarms_for_metric(
                                cloudwatch_client, 
                                metric_name, 
                                metric_namespace
                            )
                            
                            # Store status for this specific filter and metric combination
                            status_key = f"{filter_name}:{metric_name}"
                            report.resource_ids_status[status_key] = bool(alarms)

                            # If no alarms are found, mark the check as failed
                            if not alarms:
                                report.passed = False

                except KeyError:
                    # In case of any missing keys, mark the report as failed
                    report.passed = False
                    return report

            # If no VPC-related filters were found, mark the check as failed
            if not vpc_filters_found:
                report.passed = False
                report.resource_ids_status["NoVPCFilters"] = False
                return report

        except (ClientError, BotoCoreError, Exception):
            # If there are any exceptions, mark the report as failed
            report.passed = False
            return report

        # Final check: If all resource status values are True, mark the check as passed
        report.passed = all(status for status in report.resource_ids_status.values())

        return report
