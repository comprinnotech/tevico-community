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


class cloudfront_waf_protection_enabled(Check):
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
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudFront distributions found."
                    )
                )
                return report  # Early exit since there are no distributions to check

            for distribution in distributions:
                distribution_id = distribution['Id']
                distribution_arn = distribution['ARN']
                waf_association = distribution.get('WebACLId', '')
                is_waf_enabled = bool(waf_association)
                
                status = CheckStatus.PASSED if is_waf_enabled else CheckStatus.FAILED
                summary = (
                    f"CloudFront distribution '{distribution_id}' has WAF protection enabled (WebACL ID: {waf_association})."
                    if is_waf_enabled else
                    f"CloudFront distribution '{distribution_id}' does NOT have WAF protection enabled."
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
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving CloudFront distributions.",
                    exception=str(e)
                )
            )

        return report
