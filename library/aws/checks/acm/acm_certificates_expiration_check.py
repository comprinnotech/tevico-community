"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12

This module implements a check to verify if ACM certificates are approaching expiration.
It identifies certificates that will expire within a specified threshold period,
helping prevent service disruptions due to expired certificates.
"""

import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class acm_certificates_expiration_check(Check):
    """
    Check implementation to monitor ACM certificate expiration dates.
    Identifies certificates that are approaching their expiration date
    within a defined threshold period.
    """

    # Default threshold for certificate expiration warning (in days)
    EXPIRATION_THRESHOLD_DAYS = 7

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Executes the ACM certificate expiration check.
        A certificate fails if it will expire within the threshold period.

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
                                
                                # Extract expiration date
                                not_after = cert_details['Certificate']['NotAfter']
                                
                                # Get current time in UTC for comparison
                                current_time = datetime.now(timezone.utc)
                                
                                # Calculate days until expiration
                                days_until_expiration = (not_after - current_time).days
                                
                                # Check if certificate expires within threshold
                                is_valid = days_until_expiration > self.EXPIRATION_THRESHOLD_DAYS
                                report.resource_ids_status[cert_arn] = is_valid
                                
                                # If any certificate fails, the overall check fails
                                if not is_valid:
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
            for cert in processed_certificates:  # Using processed_certificates instead of checking locals()
                try:
                    cert_arn = cert['CertificateArn']
                    report.resource_ids_status[cert_arn] = False
                except (KeyError, Exception):
                    continue
            report.passed = False

        return report
