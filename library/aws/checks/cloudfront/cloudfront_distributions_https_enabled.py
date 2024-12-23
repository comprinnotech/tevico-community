"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError, BotoCoreError

class cloudfront_distributions_https_enabled(Check):
    # Helper method to fetch the list of CloudFront distributions
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    # Helper method to check if HTTPS is enforced for a distribution
    def _check_https_enabled(self, distribution):
        distribution_id = distribution['Id']
        # Retrieve the default cache behavior configuration
        default_cache_behavior = distribution.get('DefaultCacheBehavior', {})
        # Check the ViewerProtocolPolicy setting
        viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', '')
        # If policy is not 'redirect-to-https' or 'https-only', HTTPS is not enforced
        if viewer_protocol_policy not in ['redirect-to-https', 'https-only']:
            return distribution_id, False
        return distribution_id, True

    # Main method to execute the check for HTTPS enforcement
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True  # Assume success unless a failure is detected

        try:
            # Fetch all CloudFront distributions
            distributions = self._get_distributions(client)

            if not distributions:  # If no distributions exist, mark the report as passed
                report.resource_ids_status['NoDistributions'] = True
                return report

            for distribution in distributions:
                try:
                    # Check if HTTPS is enabled for the current distribution
                    dist_id, https_enabled = self._check_https_enabled(distribution)
                    report.resource_ids_status[dist_id] = https_enabled

                    # If HTTPS is not enabled, update the report status
                    if not https_enabled:
                        report.passed = False

                except KeyError:
                    # Handle cases where the distribution data is incomplete or malformed
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report

