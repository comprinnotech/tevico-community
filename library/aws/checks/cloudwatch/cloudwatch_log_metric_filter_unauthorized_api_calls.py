"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
import re

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_unauthorized_api_calls(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudwatch_client = connection.client('logs')
        
        filters = []
        paginator = cloudwatch_client.get_paginator('describe_metric_filters')
        
        for page in paginator.paginate():
            filters.extend(page.get('metricFilters', []))

        if not filters:
            report.status = ResourceStatus.FAILED
            return report

        pattern = r"\$\.errorCode\s*=\s*.?\*UnauthorizedOperation.+\$\.errorCode\s*=\s*.?AccessDenied\*"

        for filter in filters:
            filter_name = filter['filterName']
            filter_pattern = filter.get('filterPattern', '')

            if re.search(pattern, filter_pattern):
                report.resource_ids_status[filter_name] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[filter_name] = False

        return report
