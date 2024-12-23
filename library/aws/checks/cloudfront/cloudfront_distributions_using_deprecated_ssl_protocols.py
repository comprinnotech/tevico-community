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
    def _get_distributions(self, client):
        response = client.list_distributions()
        return response.get('DistributionList', {}).get('Items', [])

    def _check_deprecated_ssl_protocol(self, distribution, deprecated_protocols):
        distribution_id = distribution['Id']
        viewer_certificate = distribution.get('ViewerCertificate', {})
        minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion', '')
        if minimum_protocol_version in deprecated_protocols:
            return distribution_id, False
        return distribution_id, True

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True
        deprecated_protocols = ['SSLv3', 'TLSv1', 'TLSv1.1']

        try:
            distributions = self._get_distributions(client)

            if not distributions:
                return report

            for distribution in distributions:
                try:
                    dist_id, status = self._check_deprecated_ssl_protocol(distribution, deprecated_protocols)
                    report.resource_ids_status[dist_id] = status

                    if not status:
                        report.passed = False

                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
