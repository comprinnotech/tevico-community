"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-14
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_waf_protection_enabled(Check):
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _check_waf_protection(self, distribution):
        distribution_id = distribution['Id']
        web_acl_id = distribution.get('WebACLId')
        return distribution_id, bool(web_acl_id)

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            distributions = self._get_distributions(client)

            if not distributions:
                return report

            for distribution in distributions:
                try:
                    dist_id, is_protected = self._check_waf_protection(distribution)
                    report.resource_ids_status[dist_id] = is_protected
                    
                    if not is_protected:
                        report.passed = False
                
                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
