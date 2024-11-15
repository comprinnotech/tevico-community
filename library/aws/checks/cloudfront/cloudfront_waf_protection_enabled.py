"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-14
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_waf_protection_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('cloudfront')
        response = client.list_distributions()

        distributions = response.get('DistributionList', {}).get('Items', [])
        if not distributions:
            report.passed = True
            return report

        for distribution in distributions:
            distribution_id = distribution['Id']
            web_acl_id = distribution.get('WebACLId')

            if web_acl_id:
                report.resource_ids_status[distribution_id] = True
            else:
                report.passed = False
                report.resource_ids_status[distribution_id] = False

        return report
