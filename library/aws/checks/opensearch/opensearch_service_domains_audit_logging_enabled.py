"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-04
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class opensearch_service_domains_audit_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("opensearch")

            # Pagination for listing all OpenSearch domains
            domain_names = []
            next_token = None

            while True:
                response = client.list_domain_names(NextToken=next_token) if next_token else client.list_domain_names()
                domain_names.extend(response.get("DomainNames", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no OpenSearch domains exist, mark as NOT_APPLICABLE
            if not domain_names:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No OpenSearch domains found.",
                    )
                )
                return report

            # Check each OpenSearch domain for audit logging
            for dn in domain_names:
                domain_name = dn["DomainName"]

                try:

                    domain_status  = client.describe_domain(DomainName=domain_name)["DomainStatus"]
                    domain_arn = domain_status["ARN"]
                    resource = AwsResource(arn=domain_arn)
                    log_options = domain_status.get("LogPublishingOptions", {})

                    # Check if Audit Logging is enabled
                    audit_logging_enabled = (
                        log_options.get("AUDIT_LOGS", {}).get("Enabled", False)
                    )

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.PASSED if audit_logging_enabled else CheckStatus.FAILED,
                            summary=f"Audit logging {'enabled' if audit_logging_enabled else 'not enabled'} for domain {domain_name}."
                        )
                    )

                    if not audit_logging_enabled:
                        report.status = CheckStatus.FAILED  # Mark overall check as FAILED if any domain is non-compliant

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=domain_name),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving audit logging status for {domain_name}: {str(e)}",
                            exception=str(e),
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving OpenSearch domains: {str(e)}",
                    exception=str(e),
                )
            )

        return report
