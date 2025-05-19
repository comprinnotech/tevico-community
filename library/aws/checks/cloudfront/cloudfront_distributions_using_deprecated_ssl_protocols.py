"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-09
"""
import boto3
from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class cloudfront_distributions_using_deprecated_ssl_protocols(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__, status=CheckStatus.PASSED, resource_ids_status=[])

        try:
            distributions = []
            next_marker = None

            while True:
                response = client.list_distributions(Marker=next_marker) if next_marker else client.list_distributions()
                distribution_list = response.get('DistributionList', {})

                distributions.extend(distribution_list.get('Items', []))
                next_marker = distribution_list.get('NextMarker')

                if not next_marker:
                    break

            if not distributions:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="CloudFront"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudFront distributions found."
                    )
                )
                return report  # Early exit since there are no distributions to check

            deprecated_protocols = {"SSLv3", "TLSv1", "TLSv1.1"}

            for distribution in distributions:
                distribution_id = distribution['Id']
                distribution_arn = distribution['ARN']
                security_policy = distribution.get('ViewerCertificate', {}).get('MinimumProtocolVersion', 'TLSv1.2')
                is_deprecated = security_policy in deprecated_protocols
                
                status = CheckStatus.FAILED if is_deprecated else CheckStatus.PASSED
                summary = (
                    f"CloudFront distribution '{distribution_id}' is using deprecated SSL/TLS protocol: {security_policy}."
                    if is_deprecated else
                    f"CloudFront distribution '{distribution_id}' is using secure SSL/TLS protocol: {security_policy}."
                )
                
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(arn=distribution_arn),
                        status=status,
                        summary=summary
                    )
                )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="CloudFront"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving CloudFront distributions.",
                    exception=str(e)
                )
            )

        return report
