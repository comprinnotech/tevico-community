"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12

This module implements a check to verify if Certificate Transparency (CT) logging
is enabled for ACM certificates. CT logging helps detect and prevent malicious
or mistakenly issued certificates by making them publicly visible.
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class acm_certificates_transparency_logs_enabled(Check):
    """
    Check implementation to verify Certificate Transparency logging status
    for ACM certificates. Ensures certificates are configured to log to public
    Certificate Transparency logs for enhanced security and transparency.
    """
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Executes the Certificate Transparency logging check.
        A certificate passes if CT logging is enabled (default is ENABLED).

        Args:
            connection (boto3.Session): Active AWS session for making API calls

        Returns:
            CheckReport: Report containing the analysis results for each certificate
        """
        # Initialize report and certificates list
        report = CheckReport(name=__name__)
        report.passed = True
        processed_certificates = []

        try:
            # Initialize ACM client
            client = connection.client('acm')
            
            try:
                # List all ACM certificates using pagination
                paginator = client.get_paginator('list_certificates')
                for page in paginator.paginate():
                    # Store certificates as we process them
                    certificates = page['CertificateSummaryList']
                    processed_certificates.extend(certificates)
                    
                    # Process each certificate
                    for cert in certificates:
                        try:
                            cert_arn = cert['CertificateArn']
                            
                            try:
                                # Get detailed certificate information
                                cert_details = client.describe_certificate(
                                    CertificateArn=cert_arn
                                )
                                
                                # Extract CT logging preference
                                # Default to 'ENABLED' if not specified
                                transparency_logging = (
                                    cert_details.get('Certificate', {})
                                    .get('Options', {})
                                    .get('CertificateTransparencyLoggingPreference', 'ENABLED')
                                )
                                
                                # Check if CT logging is enabled
                                is_logging_enabled = transparency_logging == 'ENABLED'
                                report.resource_ids_status[cert_arn] = is_logging_enabled
                                
                                # If any certificate has CT logging disabled, the check fails
                                if not is_logging_enabled:
                                    report.passed = False
                                    
                            except (ClientError, BotoCoreError) as e:
                                # Handle errors in getting certificate details
                                report.resource_ids_status[cert_arn] = False
                                report.passed = False
                                
                        except KeyError:
                            # Handle missing certificate ARN
                            continue
                            
            except (ClientError, BotoCoreError):
                # Handle errors in listing certificates
                report.passed = False
                return report
                
        except (ClientError, BotoCoreError, Exception):
            # Handle any unexpected errors
            # Mark all processed certificates as failed
            for cert in processed_certificates:
                try:
                    cert_arn = cert['CertificateArn']
                    report.resource_ids_status[cert_arn] = False
                except (KeyError, Exception):
                    continue
            report.passed = False

        return report
