"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-09
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudfront_distributions_https_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize CloudFront client
        client = connection.client('cloudfront')

        report = CheckReport(name=__name__)

        # Initialize report status as 'Passed' unless we find a distribution without HTTPS enabled
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

            # Iterate over distributions to check HTTPS status
            for distribution in distributions:
                distribution_id = distribution['Id']
                distribution_arn = distribution['ARN']
                default_cache_behavior = distribution.get('DefaultCacheBehavior', {})
                viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', 'allow-all')
       

                # Log the HTTPS status of each distribution (True or False
                if viewer_protocol_policy in ['redirect-to-https', 'https-only']:
                    report.status = CheckStatus.PASSED  # Mark report as 'Failed' if any distribution is not using HTTPS
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=distribution_arn),
                            status=CheckStatus.PASSED,
                            summary=f"{distribution_id} has {viewer_protocol_policy}."
                        )
                    )
                else:
                    report.status = CheckStatus.FAILED  # Mark report as 'Failed' if any distribution is not using HTTPS
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=distribution_arn),
                            status=CheckStatus.FAILED,
                            summary=f"{distribution_id} has {viewer_protocol_policy}."
                        )
                    )
                    

        except Exception as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append( 
                ResourceStatus(
                    resource=GeneralResource(resource=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error while fetching CloudFront distribution config",     
                    exception=e
                )
            )            

        return report
