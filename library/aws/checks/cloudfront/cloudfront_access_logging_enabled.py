"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-01-02
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_access_logging_enabled(Check):

    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _get_distribution_config(self, client, distribution_id):
        try:
            response = client.get_distribution_config(Id=distribution_id)
            return response.get('DistributionConfig', {})
        except (ClientError, BotoCoreError):
            return {}

    def _check_logging_enabled(self, client, distribution_id):
        dist_config = self._get_distribution_config(client, distribution_id)
        dist_logging = dist_config.get('Logging', {})
        return dist_logging.get('Enabled', False)

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = False

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                report.resource_ids_status['NoDistributions'] = False
                return report

            all_distributions_logging = True

            for distribution in distributions:
                try:
                    dist_id = distribution['Id']
                    logging_enabled = self._check_logging_enabled(client, dist_id)
                    report.resource_ids_status[dist_id] = logging_enabled

                    if not logging_enabled:
                        all_distributions_logging = False

                except KeyError:
                    report.resource_ids_status[distribution.get('Id', 'Unknown')] = False
                    all_distributions_logging = False

            report.passed = all_distributions_logging

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report

