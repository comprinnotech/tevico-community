"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-09
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudfront_distributions_using_deprecated_ssl_protocols(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize CloudFront client
        client = connection.client('cloudfront')

        report = CheckReport(name=__name__)

        # Initialize report status as 'Passed' unless we find a distribution using deprecated SSL protocols
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Initialize pagination
            distributions = []
            next_marker = None

            while True:
                # Fetch distributions with pagination
                if next_marker:
                    res = client.list_distributions(Marker=next_marker)
                else:
                    res = client.list_distributions()

                distributions.extend(res.get('DistributionList', {}).get('Items', []))
                next_marker = res.get('NextMarker', None)

                if not next_marker:
                    break

            # Iterate over distributions to check SSL protocols
            for distribution in distributions:
                distribution_id = distribution['Id']
                distribution_arn = distribution['ARN']

                # Fetch the SSL configuration for the distribution
                viewer_certificate = distribution.get('ViewerCertificate', {})
                ssl_protocols = viewer_certificate.get('MinimumProtocolVersion')
                

                # Check for deprecated SSL protocols (TLSv1, TLSv1.1, SSLv3)
                if ssl_protocols in ['TLSv1', 'TLSv1.1', 'SSLv3']:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=distribution_arn),
                            status=CheckStatus.FAILED,
                            summary=f"{distribution_id} uses the deprecated SSL protocol {ssl_protocols}."
                        )
                    )
                    report.status = CheckStatus.FAILED  # Mark report as 'Failed' if any distribution is using deprecated SSL protocols
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=distribution_arn),
                            status=CheckStatus.PASSED,
                            summary=f"{distribution_id} uses {ssl_protocols}, not a deprecated SSL protocol."
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error while fetching CloudFront distribution config",
                    exception=str(e)
                )
            )

        return report
