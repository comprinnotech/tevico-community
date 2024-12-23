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
    # Helper method to fetch the list of CloudFront distributions
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    # Helper method to check if WAF protection is enabled for a distribution
    def _check_waf_protection(self, distribution):
        distribution_id = distribution['Id']
        # Check if the distribution has a WebACLId, indicating WAF protection is enabled
        web_acl_id = distribution.get('WebACLId')
        return distribution_id, bool(web_acl_id)

    # Main method to execute the check for WAF protection
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True  # Assume success unless a failure is detected

        try:
            # Fetch all CloudFront distributions
            distributions = self._get_distributions(client)

            if not distributions:  # If no distributions exist, return the report as passed
                return report

            for distribution in distributions:
                try:
                    # Check if WAF protection is enabled for the current distribution
                    dist_id, is_protected = self._check_waf_protection(distribution)
                    report.resource_ids_status[dist_id] = is_protected

                    # If WAF protection is not enabled, update the report status
                    if not is_protected:
                        report.passed = False

                except KeyError:
                    # Handle cases where expected keys are missing in the distribution configuration
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report
