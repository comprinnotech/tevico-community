"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-09
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class acm_certificates_transparency_logs_enabled(Check):

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
                    # Get detailed certificate information
                    cert_details = client.describe_certificate(CertificateArn=cert_arn)
                    transparency_logging = cert_details.get("Certificate", {}).get("Options", {}).get("CertificateTransparencyLoggingPreference", "ENABLED")

                    if transparency_logging != "ENABLED":
                        summary = f"Certificate {cert_arn} has transparency logging disabled."
                        status = CheckStatus.FAILED
                    else:
                        summary = f"Certificate {cert_arn} has transparency logging enabled."
                        status = CheckStatus.PASSED

                    # Append result
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=cert_arn),
                            status=status,
                            summary=summary
                        )
                    )

                    # Mark check as failed if any certificate has logging disabled
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
