"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""


import boto3
import re
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


import boto3
import re
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_policy_changes(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('logs')

        try:
            response = cloudwatch_client.describe_metric_filters()
            filters = response.get('metricFilters', [])
        except Exception:
            report.passed = False
            return report

        if not filters:
            
            report.passed = True
            return report

        pattern = r"\$\.eventName\s*=\s*.?DeleteGroupPolicy.+\$\.eventName\s*=\s*.?DeleteRolePolicy.+\$\.eventName\s*=\s*.?DeleteUserPolicy.+\$\.eventName\s*=\s*.?PutGroupPolicy.+\$\.eventName\s*=\s*.?PutRolePolicy.+\$\.eventName\s*=\s*.?PutUserPolicy.+\$\.eventName\s*=\s*.?CreatePolicy.+\$\.eventName\s*=\s*.?DeletePolicy.+\$\.eventName\s*=\s*.?CreatePolicyVersion.+\$\.eventName\s*=\s*.?DeletePolicyVersion.+\$\.eventName\s*=\s*.?AttachRolePolicy.+\$\.eventName\s*=\s*.?DetachRolePolicy.+\$\.eventName\s*=\s*.?AttachUserPolicy.+\$\.eventName\s*=\s*.?DetachUserPolicy.+\$\.eventName\s*=\s*.?AttachGroupPolicy.+\$\.eventName\s*=\s*.?DetachGroupPolicy.?"

        failed_filters = False

        for filter in filters:
            try:
                filter_name = filter['filterName']
                filter_pattern = filter.get('filterPattern', '')

                if re.search(pattern, filter_pattern):
                    report.resource_ids_status[filter_name] = True
                else:
                    report.resource_ids_status[filter_name] = False
                    failed_filters = True

            except Exception:
                report.resource_ids_status[filter_name] = False
                failed_filters = True
                continue

      
        if failed_filters:
            report.passed = False
        else:
            report.passed = True

        return report
