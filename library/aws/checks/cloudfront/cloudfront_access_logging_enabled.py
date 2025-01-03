"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_access_logging_enabled(Check):

    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _check_logging_enabled(self, distribution):
        distribution_id = distribution['Id']
        dist_config = distribution.get('DistributionConfig', {})
        dist_logging = dist_config.get('Logging', {})
        return distribution_id, dist_logging.get('Enabled', False)

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = False  # Start with False

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                report.resource_ids_status['NoDistributions'] = False
                return report

            # Start with assumption all distributions will pass
            all_distributions_logging = True

            for distribution in distributions:
                try:
                    dist_id, logging_enabled = self._check_logging_enabled(distribution)
                    report.resource_ids_status[dist_id] = logging_enabled

                    # If logging is disabled for any distribution, mark for failure
                    if not logging_enabled:
                        all_distributions_logging = False

                except KeyError:
                    report.resource_ids_status[distribution.get('Id', 'Unknown')] = False
                    all_distributions_logging = False

            # Set final pass/fail status after checking all distributions
            report.passed = all_distributions_logging

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report



