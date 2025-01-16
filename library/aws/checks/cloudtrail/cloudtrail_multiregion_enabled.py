"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudtrail_multiregion_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the CloudTrail client
        cloudtrail_client = connection.client('cloudtrail')

        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Retrieve the CloudTrail configuration
            trail_info = cloudtrail_client.describe_trails()
            if not trail_info['trailList']:
                logging.info("No CloudTrails found")
                return report

            # Iterate over all trails to check multi-region status
            for trail in trail_info['trailList']:
                trail_name = trail.get('Name')
                multi_region = trail.get('IsMultiRegionTrail', False)

                if multi_region:
                    # Multi-region logging is enabled
                    report.resource_ids_status[
                        f"CloudTrail {trail_name} - Multi-Region: Enabled"
                    ] = True
                else:
                    # Multi-region logging is not enabled
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[
                        f"CloudTrail {trail_name} - Multi-Region: Disabled"
                    ] = False

        except Exception as e:
            logging.error(f"Error while retrieving CloudTrail trails: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
