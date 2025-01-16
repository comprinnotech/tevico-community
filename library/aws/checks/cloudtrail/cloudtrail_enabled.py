"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudtrail_enabled(Check):
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
                report.status = ResourceStatus.FAILED
                report.resource_ids_status["No CloudTrail found"] = False
                return report

            # Check if any trail is enabled
            for trail in trail_info['trailList']:
                trail_name = trail.get('Name')
                status = trail.get('Status', {}).get('IsLogging', False)

                if status:
                    # CloudTrail is enabled for this trail
                    report.resource_ids_status[
                        f"CloudTrail {trail_name} - Logging: Enabled"
                    ] = True
                else:
                    # CloudTrail is not enabled for this trail
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[
                        f"CloudTrail {trail_name} - Logging: Disabled"
                    ] = False

        except Exception as e:
            logging.error(f"Error while checking CloudTrail status: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
