"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudfront_cloudwatch_logging_enabled(Check):

    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _check_cloudwatch_logging_enabled(self, client, distribution_id):
        try:
            response = client.get_distribution(Id=distribution_id)
            distribution_config = response['Distribution']['DistributionConfig']
            logging_config = distribution_config.get('Logging', {})
            
            return (logging_config.get('Enabled', False) and 
                   logging_config.get('DestinationType') == 'CWL')
            
        except ClientError:
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = False  # Start with False
        
        try:
            distributions = self._get_distributions(client)

            if not distributions:
                report.resource_ids_status['NoDistributions'] = False
                return report

            # Track if all distributions have CloudWatch logging enabled
            all_distributions_logging = True

            for distribution in distributions:
                try:
                    distribution_id = distribution['Id']
                    cloudwatch_enabled = self._check_cloudwatch_logging_enabled(client, distribution_id)
                    report.resource_ids_status[distribution_id] = cloudwatch_enabled

                    if not cloudwatch_enabled:
                        all_distributions_logging = False

                except KeyError:
                    report.resource_ids_status[distribution.get('Id', 'Unknown')] = False
                    all_distributions_logging = False

            # Set final status based on all distributions
            report.passed = all_distributions_logging

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report

