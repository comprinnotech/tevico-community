"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""


import boto3
import re
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class cloudwatch_log_metric_filter_policy_changes(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('logs')
        
        response = cloudwatch_client.describe_metric_filters()

        filters = response.get('metricFilters', [])
        if not filters:
            report.status = ResourceStatus.FAILED
            return report

        pattern = r"\$\.eventName\s*=\s*.?DeleteGroupPolicy.+\$\.eventName\s*=\s*.?DeleteRolePolicy.+\$\.eventName\s*=\s*.?DeleteUserPolicy.+\$\.eventName\s*=\s*.?PutGroupPolicy.+\$\.eventName\s*=\s*.?PutRolePolicy.+\$\.eventName\s*=\s*.?PutUserPolicy.+\$\.eventName\s*=\s*.?CreatePolicy.+\$\.eventName\s*=\s*.?DeletePolicy.+\$\.eventName\s*=\s*.?CreatePolicyVersion.+\$\.eventName\s*=\s*.?DeletePolicyVersion.+\$\.eventName\s*=\s*.?AttachRolePolicy.+\$\.eventName\s*=\s*.?DetachRolePolicy.+\$\.eventName\s*=\s*.?AttachUserPolicy.+\$\.eventName\s*=\s*.?DetachUserPolicy.+\$\.eventName\s*=\s*.?AttachGroupPolicy.+\$\.eventName\s*=\s*.?DetachGroupPolicy.?"

        for filter in filters:
            filter_name = filter['filterName']
            filter_pattern = filter['filterPattern']

            if re.search(pattern, filter_pattern):
                report.resource_ids_status[filter_name] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[filter_name] = False

        return report
