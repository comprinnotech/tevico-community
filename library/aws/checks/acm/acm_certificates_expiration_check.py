"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12
"""

import boto3
from datetime import datetime, timedelta, timezone
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class acm_certificates_expiration_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('acm')
        report = CheckReport(name=__name__)
        report.passed = True
        threshold_days = 7  # Expiration threshold in days

        # List all ACM certificates
        paginator = client.get_paginator('list_certificates')
        for page in paginator.paginate():
            certificates = page['CertificateSummaryList']
            for cert in certificates:
                cert_arn = cert['CertificateArn']
                
                # Get certificate details
                cert_details = client.describe_certificate(CertificateArn=cert_arn)
                not_after = cert_details['Certificate']['NotAfter']
                
                # Convert current time to timezone-aware for comparison
                current_time = datetime.now(timezone.utc)
                
                # Check if the certificate expires within the threshold
                days_until_expiration = (not_after - current_time).days
                if days_until_expiration <= threshold_days:
                    report.resource_ids_status[cert_arn] = False
                    report.passed = False
                else:
                    report.resource_ids_status[cert_arn] = True

        return report

