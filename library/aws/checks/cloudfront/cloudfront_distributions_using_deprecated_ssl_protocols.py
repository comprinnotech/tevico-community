"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_distributions_using_deprecated_ssl_protocols(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.status = True

        # List CloudFront distributions
        distributions = client.list_distributions()
        deprecated_protocols = ['SSLv3', 'TLSv1', 'TLSv1.1']

        if ('DistributionList' in distributions and 
            'Items' in distributions['DistributionList'] and 
            distributions['DistributionList']['Items']):
            
            for distribution in distributions['DistributionList']['Items']:
                distribution_id = distribution['Id']
                viewer_certificate = distribution.get('ViewerCertificate', {})

                minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion', '')
                if minimum_protocol_version in deprecated_protocols:
                    report.resource_ids_status[distribution_id] = False
                    report.status = False
                else:
                    report.resource_ids_status[distribution_id] = True

        return report
