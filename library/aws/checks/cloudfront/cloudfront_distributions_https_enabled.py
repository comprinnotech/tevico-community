"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError, BotoCoreError

class cloudfront_distributions_https_enabled(Check):

    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _check_https_enabled(self, distribution):
        distribution_id = distribution['Id']
        default_cache_behavior = distribution.get('DefaultCacheBehavior', {})
        viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', '')

        # Check if HTTPS is enforced
        is_https_enforced = viewer_protocol_policy in ['redirect-to-https', 'https-only']
        return distribution_id, is_https_enforced

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = False  # Start with False

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                report.resource_ids_status['NoDistributions'] = False
                return report

            # Track if all distributions enforce HTTPS
            all_distributions_https = True

            for distribution in distributions:
                try:
                    dist_id, https_enabled = self._check_https_enabled(distribution)
                    report.resource_ids_status[dist_id] = https_enabled

                    if not https_enabled:
                        all_distributions_https = False

                except KeyError:
                    report.resource_ids_status[distribution.get('Id', 'Unknown')] = False
                    all_distributions_https = False

            # Set final status based on all distributions
            report.passed = all_distributions_https

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report
