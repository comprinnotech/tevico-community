"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""


import boto3
import re
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class cloudwatch_log_metric_filter_authentication_failures(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('logs')

        pattern = r"\$\.eventName\s*=\s*.?ConsoleLogin.+\$\.errorMessage\s*=\s*.?Failed authentication.?"

        log_groups = cloudwatch_client.describe_log_groups()

        if not log_groups['logGroups']:
            report.status = ResourceStatus.FAILED
            return report

        for log_group in log_groups['logGroups']:
            log_group_name = log_group['logGroupName']
            filters = cloudwatch_client.describe_metric_filters(
                logGroupName=log_group_name
            )

            found_filter = False
            for filter in filters.get('metricFilters', []):
                if re.search(pattern, filter['filterPattern']):
                    found_filter = True
                    break

            if found_filter:
                report.resource_ids_status[log_group_name] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[log_group_name] = False

        return report
