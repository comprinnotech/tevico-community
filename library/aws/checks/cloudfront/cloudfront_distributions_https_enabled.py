"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-09
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudfront_distributions_https_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize CloudFront client
        client = connection.client('cloudfront')

        report = CheckReport(name=__name__)

        # Initialize report status as 'Passed' unless we find a distribution without HTTPS enabled
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

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
                default_cache_behavior = distribution.get('DefaultCacheBehavior', {})
                viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', 'allow-all')
       

                # Log the HTTPS status of each distribution (True or False
                if viewer_protocol_policy in ['redirect-to-https', 'https-only']:
                    report.status = ResourceStatus.PASSED  # Mark report as 'Failed' if any distribution is not using HTTPS
                    report.resource_ids_status[f"{distribution_id} has  {viewer_protocol_policy}."] = True
                else:
                    report.status = ResourceStatus.FAILED  # Mark report as 'Failed' if any distribution is not using HTTPS
                    report.resource_ids_status[f"{distribution_id} has  {viewer_protocol_policy}."] = False
                    

        except Exception as e:
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
