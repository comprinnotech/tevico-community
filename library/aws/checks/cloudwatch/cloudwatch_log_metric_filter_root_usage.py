"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_security_group_changes(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('logs')
        response = cloudwatch_client.describe_metric_filters()

        metric_filters = response.get('metricFilters', [])
        if not metric_filters:
            report.status = ResourceStatus.FAILED
            return report

        for filter in metric_filters:
            filter_name = filter['filterName']
            filter_pattern = filter['filterPattern']

            if 'security-group' in filter_pattern.lower():
                report.resource_ids_status[filter_name] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[filter_name] = False

        return report
