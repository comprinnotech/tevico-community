"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError, BotoCoreError

class cloudfront_distributions_using_deprecated_ssl_protocols(Check):

    # Helper method to fetch the list of CloudFront distributions
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    # Helper method to check if a distribution is using a deprecated SSL protocol
    def _check_deprecated_ssl_protocol(self, distribution, deprecated_protocols):
        distribution_id = distribution['Id']

        # Retrieve the ViewerCertificate configuration for the distribution
        viewer_certificate = distribution.get('ViewerCertificate', {})

        # Get the minimum protocol version configured for the distribution
        minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion', '')

        # If the protocol is in the list of deprecated protocols, mark it as not compliant
        if minimum_protocol_version in deprecated_protocols:
            return distribution_id, False

        return distribution_id, True

    # Main method to execute the check for deprecated SSL protocols
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True  # Assume success unless a failure is detected

        # List of deprecated SSL protocols
        deprecated_protocols = ['SSLv3', 'TLSv1', 'TLSv1.1']

        try:
            # Fetch all CloudFront distributions
            distributions = self._get_distributions(client)

            if not distributions:  # If no distributions exist, return the report as passed
                report.resource_ids_status['NoDistributions'] = True
                return report

            for distribution in distributions:
                try:
                    # Check if the distribution uses a deprecated SSL protocol
                    dist_id, status = self._check_deprecated_ssl_protocol(distribution, deprecated_protocols)
                    report.resource_ids_status[dist_id] = status

                    # If a deprecated protocol is found, update the report status
                    if not status:
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


