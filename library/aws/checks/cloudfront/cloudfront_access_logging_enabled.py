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
        report.passed = True

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                return report

            for distribution in distributions:
                try:
                    dist_id, logging_enabled = self._check_logging_enabled(distribution)
                    report.resource_ids_status[dist_id] = logging_enabled

                    if not logging_enabled:
                        report.passed = False

                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report

