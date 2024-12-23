"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_cloudwatch_logging_enabled(Check):
    # Helper method to fetch the list of CloudFront distributions
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    # Helper method to check if CloudWatch logging is enabled for a distribution
    def _check_logging_enabled(self, distribution):
        distribution_id = distribution['Id']
        # Retrieve the logging configuration for the distribution
        logging_config = distribution.get('Logging', {})
        return distribution_id, logging_config.get('Enabled', False)

    # Main method to execute the check for CloudFront CloudWatch logging
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True  # Assume success unless a failure is found

        try:
            # Fetch all CloudFront distributions
            distributions = self._get_distributions(client)

            if not distributions:  # If no distributions exist, the check passes
                return report

            for distribution in distributions:
                try:
                    # Check if logging is enabled for the current distribution
                    dist_id, logging_enabled = self._check_logging_enabled(distribution)
                    report.resource_ids_status[dist_id] = logging_enabled

                    # If logging is disabled, update the report to reflect the failure
                    if not logging_enabled:
                        report.passed = False

                except KeyError:
                    # Handle cases where the distribution data is incomplete or malformed
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API or generic errors that occur during execution
            report.passed = False
            return report

        return report
