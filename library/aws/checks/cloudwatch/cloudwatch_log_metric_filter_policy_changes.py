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


class cloudwatch_log_metric_filter_policy_changes(Check):

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

        pattern = r"\$\.eventName\s*=\s*.?DeleteGroupPolicy.+\$\.eventName\s*=\s*.?DeleteRolePolicy.+\$\.eventName\s*=\s*.?DeleteUserPolicy.+\$\.eventName\s*=\s*.?PutGroupPolicy.+\$\.eventName\s*=\s*.?PutRolePolicy.+\$\.eventName\s*=\s*.?PutUserPolicy.+\$\.eventName\s*=\s*.?CreatePolicy.+\$\.eventName\s*=\s*.?DeletePolicy.+\$\.eventName\s*=\s*.?CreatePolicyVersion.+\$\.eventName\s*=\s*.?DeletePolicyVersion.+\$\.eventName\s*=\s*.?AttachRolePolicy.+\$\.eventName\s*=\s*.?DetachRolePolicy.+\$\.eventName\s*=\s*.?AttachUserPolicy.+\$\.eventName\s*=\s*.?DetachUserPolicy.+\$\.eventName\s*=\s*.?AttachGroupPolicy.+\$\.eventName\s*=\s*.?DetachGroupPolicy.?"

        try:
            filters = self._get_metric_filters(client)

            if not filters:
                report.passed = False
                report.resource_ids_status['No relevant filters'] = False
                return report

            for filter in filters:
                try:
                    filter_name = filter['filterName']
                    filter_pattern = filter.get('filterPattern', '')

                    if re.search(pattern, filter_pattern):
                        report.resource_ids_status[filter_name] = True
                    else:
                        report.passed = False
                        report.resource_ids_status[filter_name] = False

                except KeyError:
                    report.passed = False
                    report.resource_ids_status[filter_name] = False

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['No relevant filters'] = False

        return report
