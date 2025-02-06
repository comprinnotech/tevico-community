"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-09

"""

import boto3
from datetime import datetime, timezone
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class acm_certificates_expiration_check(Check):

    # Default threshold for certificate expiration warning (in days)
    EXPIRATION_THRESHOLD_DAYS = 7

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize ACM client and check report
        client = connection.client('acm')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Use paginator to list all ACM certificates
            paginator = client.get_paginator('list_certificates')
            certificates_found = False

            for page in paginator.paginate():
                certificates = page.get('CertificateSummaryList', [])

                if certificates:
                    certificates_found = True

                for cert in certificates:
                    cert_arn = cert.get('CertificateArn')

                    try:
                        # Describe each certificate to get expiration details
                        cert_details = client.describe_certificate(CertificateArn=cert_arn)
                       
                        not_after = cert_details['Certificate'].get('NotAfter')

                        if not_after:
                            # Calculate days until expiration
                            current_time = datetime.now(timezone.utc)
                            days_until_expiration = (not_after - current_time).days

                            # Handle expired certificates gracefully
                            if days_until_expiration < 0:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=AwsResource(arn=cert_arn),
                                        status=CheckStatus.FAILED,
                                        summary="Certificate " + cert_arn + " has already expired " + days_until_expiration + " days ago."
                                    )
                                )
                                report.status = CheckStatus.FAILED
                            else:
                                # Determine if certificate is within expiration threshold
                                is_valid = days_until_expiration > self.EXPIRATION_THRESHOLD_DAYS
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=AwsResource(arn=cert_arn),
                                        status=CheckStatus.FAILED,
                                        summary="Certificate " + cert_arn + " expires in " + days_until_expiration + " days."
                                    )
                                )

                                # If any certificate is expiring soon, mark the check as failed
                                if not is_valid:
                                    report.status = CheckStatus.FAILED

                    except Exception as e:
                        # Handle errors while describing a certificate
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=cert_arn),
                                status=CheckStatus.FAILED,
                                summary="Error describing " + cert_arn + "."
                            )
                        )
                        report.status = CheckStatus.FAILED

            if not certificates_found:
                # No certificates found, mark the check as passed
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(resource=""),
                        status=CheckStatus.SKIPPED,
                        summary="No ACM certificates found."
                    )
                )
                report.status = CheckStatus.FAILED


        except Exception as e:
            # Handle errors while listing certificates
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(resource=""),
                    status=CheckStatus.SKIPPED,
                    summary="ACM listing error.",
                    exception=e
                )
            )
            report.status = CheckStatus.FAILED


        return report
