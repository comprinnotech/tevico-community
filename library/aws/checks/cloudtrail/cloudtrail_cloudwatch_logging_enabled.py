"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudtrail_cloudwatch_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the CloudTrail client
        cloudtrail_client = connection.client('cloudtrail')

        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Retrieve the CloudTrail configuration
            trail_info = cloudtrail_client.describe_trails()
            if not trail_info['trailList']:
                logging.info("No CloudTrails found")
                return report

            # Iterate over all trails to check CloudWatch Logs integration
            for trail in trail_info['trailList']:
                trail_name = trail.get('Name')
                trail_arn = trail.get('TrailARN')
                cloudwatch_log_group = trail.get('CloudWatchLogsLogGroupArn')

                if cloudwatch_log_group:
                    # CloudWatch Logs integration is enabled
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=trail_arn),
                            status=CheckStatus.PASSED,
                            summary=f"CloudTrail {trail_name} - CloudWatch Logs: Enabled"
                        )
                    )
                else:
                    # CloudWatch Logs integration is not enabled
                    report.status = CheckStatus.FAILED
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=trail_arn),
                            status=CheckStatus.FAILED,
                            summary=f"CloudTrail {trail_name} - CloudWatch Logs: Disabled"
                        )
                    )

        except Exception as e:
            logging.error(f"Error while retrieving CloudTrail trails: {e}")
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error while retrieving CloudTrail trails",
                    exception=str(e)
                )
            )

        return report

