"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-03-28
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class route53_domains_privacy_protection_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Route53 Domains API is only available in us-east-1
            route53domains_client = connection.client('route53domains', region_name="us-east-1")

            # Get all domains
            domains = []
            paginator = route53domains_client.get_paginator('list_domains')

            for page in paginator.paginate():
                domains.extend(page.get('Domains', []))

            if not domains:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Route53 domains found."
                    )
                )
                return report

            # Check privacy protection for each domain
            for domain_info in domains:
                domain_name = domain_info['DomainName']
                domain_arn = f"arn:aws:route53domains:::{domain_name}"

                try:
                    domain_detail = route53domains_client.get_domain_detail(DomainName=domain_name)

                    # Privacy settings
                    privacy_settings = {
                        "Admin": domain_detail.get('AdminPrivacy', False),
                        "Registrant": domain_detail.get('RegistrantPrivacy', False),
                        "Technical": domain_detail.get('TechPrivacy', False)
                    }

                    # Find which are missing
                    missing_privacy = [role for role, enabled in privacy_settings.items() if not enabled]

                    if not missing_privacy:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=domain_arn),
                                status=CheckStatus.PASSED,
                                summary=f"Domain {domain_name} has complete privacy protection enabled."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=domain_arn),
                                status=CheckStatus.FAILED,
                                summary=f"Domain {domain_name} is missing privacy protection for: {', '.join(missing_privacy)} contact information."
                            )
                        )

                except (BotoCoreError, ClientError) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=domain_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Failed to retrieve privacy settings for domain {domain_name}.",
                            exception=str(e)
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Encountered an error while retrieving Route53 domains.",
                    exception=str(e)
                )
            )

        return report
