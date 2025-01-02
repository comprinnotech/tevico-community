"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""
import boto3
import re
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudwatch_log_metric_filter_authentication_failures(Check):

    def _get_metric_filters(self, client):
        try:
            response = client.describe_metric_filters()
            return response.get('metricFilters', [])
        except (ClientError, BotoCoreError):
            return []

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        client = connection.client('logs')

        # Pattern to match failed authentication attempts during ConsoleLogin
        pattern = r"\$\.eventName\s*=\s*.?ConsoleLogin.+\$\.errorMessage\s*=\s*.?Failed authentication.?"

        try:
            filters = self._get_metric_filters(client)

            if not filters:
                report.passed = False
                report.resource_ids_status['No relevant filters'] = False
                return report

            # Check all filters - if any filter doesn't match, the check fails
            all_filters_pass = True
            for filter in filters:
                try:
                    filter_name = filter['filterName']
                    filter_pattern = filter.get('filterPattern', '')

                    if re.search(pattern, filter_pattern):
                        report.resource_ids_status[filter_name] = True
                    else:
                        report.resource_ids_status[filter_name] = False
                        all_filters_pass = False

                except KeyError:
                    report.resource_ids_status[filter_name] = False
                    all_filters_pass = False

            # Set final status - only pass if all filters match the pattern
            report.passed = all_filters_pass

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['No relevant filters'] = False

        return report
