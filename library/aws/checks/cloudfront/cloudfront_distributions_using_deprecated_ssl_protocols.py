"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError, BotoCoreError

class cloudfront_distributions_using_deprecated_ssl_protocols(Check):

    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _check_deprecated_ssl_protocol(self, distribution, deprecated_protocols):
        distribution_id = distribution['Id']
        viewer_certificate = distribution.get('ViewerCertificate', {})
        minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion', '')

        # Check if using non-deprecated protocol
        is_secure = minimum_protocol_version not in deprecated_protocols
        return distribution_id, is_secure

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = False  # Start with False

        # List of deprecated SSL protocols
        deprecated_protocols = ['SSLv3', 'TLSv1', 'TLSv1.1']

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                report.resource_ids_status['NoDistributions'] = False
                return report

            # Track if all distributions use secure protocols
            all_distributions_secure = True

            for distribution in distributions:
                try:
                    dist_id, is_secure = self._check_deprecated_ssl_protocol(
                        distribution, 
                        deprecated_protocols
                    )
                    report.resource_ids_status[dist_id] = is_secure

                    if not is_secure:
                        all_distributions_secure = False

                except KeyError:
                    report.resource_ids_status[distribution.get('Id', 'Unknown')] = False
                    all_distributions_secure = False

            # Set final status based on all distributions
            report.passed = all_distributions_secure

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report



