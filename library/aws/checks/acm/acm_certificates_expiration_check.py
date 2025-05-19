"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-09
"""

from tokenize import Name
import boto3
from datetime import datetime, timezone
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class acm_certificates_expiration_check(Check):

    # Default threshold for certificate expiration warning (in days)
    EXPIRATION_THRESHOLD_DAYS = 7

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("acm")

        # Initialize check report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Custom pagination approach
            certificates = []
            next_token = None

            while True:
                response = client.list_certificates(NextToken=next_token) if next_token else client.list_certificates()
                certificates.extend(response.get("CertificateSummaryList", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no certificates exist
            if not certificates:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No ACM certificates found."
                    )
                )
                return report

            # Process each certificate
            for cert in certificates:
                cert_arn = cert.get("CertificateArn")

                try:
                    # Describe each certificate to get expiration details
                    cert_details = client.describe_certificate(CertificateArn=cert_arn)
                    not_after = cert_details["Certificate"].get("NotAfter")

                    if not_after:
                        # Calculate days until expiration
                        current_time = datetime.now(timezone.utc)
                        days_until_expiration = (not_after - current_time).days

                        if days_until_expiration < 0:
                            summary = f"Certificate {cert_arn} has already expired {abs(days_until_expiration)} days ago."
                            status = CheckStatus.FAILED
                        elif days_until_expiration <= self.EXPIRATION_THRESHOLD_DAYS:
                            summary = f"Certificate {cert_arn} expires in {days_until_expiration} days."
                            status = CheckStatus.FAILED
                        else:
                            summary = f"Certificate {cert_arn} is valid for {days_until_expiration} more days."
                            status = CheckStatus.PASSED

                        # Append result
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=cert_arn),
                                status=status,
                                summary=summary
                            )
                        )

                        # Mark check as failed if any certificate is within the expiration threshold
                        if status == CheckStatus.FAILED:
                            report.status = CheckStatus.FAILED

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=cert_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error describing certificate {cert_arn}.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.FAILED

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary="Error fetching ACM certificates.",
                    exception=str(e)
                )
            )
        return report
