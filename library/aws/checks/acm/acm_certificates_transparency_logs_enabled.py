"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class acm_certificates_transparency_logs_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('acm')
        report = CheckReport(name=__name__)
        report.passed = True

        # List all ACM certificates
        paginator = client.get_paginator('list_certificates')
        for page in paginator.paginate():
            certificates = page['CertificateSummaryList']
            for cert in certificates:
                cert_arn = cert['CertificateArn']
                
                # Get certificate details
                cert_details = client.describe_certificate(CertificateArn=cert_arn)
                transparency_logging = cert_details['Certificate'].get('Options', {}).get('CertificateTransparencyLoggingPreference', 'ENABLED')
                
                # Check if transparency logging is enabled
                if transparency_logging == 'ENABLED':
                    report.resource_ids_status[cert_arn] = True
                else:
                    report.resource_ids_status[cert_arn] = False
                    report.passed = False

        return report
