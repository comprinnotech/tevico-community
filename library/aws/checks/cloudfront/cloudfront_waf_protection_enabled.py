"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
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
        report.passed = False  # Start with False

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                report.resource_ids_status['NoDistributions'] = False
                return report

            # Track if all distributions have WAF enabled
            all_distributions_protected = True

            for distribution in distributions:
                try:
                    dist_id, is_protected = self._check_waf_protection(distribution)
                    report.resource_ids_status[dist_id] = is_protected

                    if not is_protected:
                        all_distributions_protected = False

                except KeyError:
                    report.resource_ids_status[distribution.get('Id', 'Unknown')] = False
                    all_distributions_protected = False

            # Set final status based on all distributions
            report.passed = all_distributions_protected

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report

