"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-14
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_access_logging_enabled(Check):
    # Helper method to fetch the list of CloudFront distributions
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    # Helper method to check if logging is enabled for a specific distribution
    def _check_logging_enabled(self, distribution):
        distribution_id = distribution['Id']
        dist_config = distribution.get('DistributionConfig', {})
        dist_logging = dist_config.get('Logging', {})
        return distribution_id, dist_logging.get('Enabled', False)

    # Main method to execute the check for CloudFront access logging
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True  # Default assumption is that all distributions pass the check

        try:
            distributions = self._get_distributions(client)  # Fetch all CloudFront distributions

            if not distributions:  # If no distributions exist, return the report as passed
                return report

            for distribution in distributions:
                try:
                    # Check if logging is enabled for the current distribution
                    dist_id, logging_enabled = self._check_logging_enabled(distribution)
                    report.resource_ids_status[dist_id] = logging_enabled

                    # If logging is disabled for any distribution, mark the report as failed
                    if not logging_enabled:
                        report.passed = False

                except KeyError:
                    # Handle cases where expected keys are missing in the response
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS and generic errors during the execution
            report.passed = False
            return report

        return report

