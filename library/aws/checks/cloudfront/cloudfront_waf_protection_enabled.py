"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class cloudfront_waf_protection_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize CloudFront client and report
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Fetch all CloudFront distributions with pagination
            distributions = []
            next_marker = None

            while True:
                response = client.list_distributions(Marker=next_marker) if next_marker else client.list_distributions()
                distributions.extend(response.get('DistributionList', {}).get('Items', []))
                next_marker = response.get('NextMarker')
                if not next_marker:
                    break

            # Check WAF association for each distribution
            for distribution in distributions:
                distribution_id = distribution['Id']
                web_acl_id = distribution.get('WebACLId', '')

                # WAF is enabled if WebACLId is not an empty string
                status = bool(web_acl_id)
                report.resource_ids_status[f"{distribution_id} WAF association: {'Enabled' if status else 'Disabled'}"] = status

                if not status:
                    report.status = ResourceStatus.FAILED  # Mark as failed if any distribution lacks WAF protection

        except Exception as e:
            logging.error(f"Error while checking CloudFront WAF protection: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
