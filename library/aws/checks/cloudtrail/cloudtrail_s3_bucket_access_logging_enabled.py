"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudtrail_s3_bucket_access_logging_enabled(Check):
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

            # Iterate over all trails
            for trail in trail_info['trailList']:
                trail_name = trail.get('Name')
                s3_bucket_name = trail.get('S3BucketName')

                if not s3_bucket_name:
                    report.resource_ids_status[f"CloudTrail {trail_name} - No S3 bucket configured"] = True
                    continue

                try:
                    # Get the region of the bucket
                    bucket_location = connection.client('s3').get_bucket_location(Bucket=s3_bucket_name)
                    bucket_region = bucket_location.get('LocationConstraint') or 'us-east-1'

                    # Create an S3 client for the bucket's region
                    s3_client = connection.client('s3', region_name=bucket_region)

                    # Check if access logging is enabled on the S3 bucket
                    logging_config = s3_client.get_bucket_logging(Bucket=s3_bucket_name)
                    logging_enabled = logging_config.get('LoggingEnabled', None)

                    if logging_enabled:
                        # Access logging is enabled
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} Access Logging: Enabled"
                        ] = True
                    else:
                        # Access logging is disabled
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} Access Logging: Disabled"
                        ] = False

                except Exception as e:
                    logging.error(
                        f"Error while checking access logging for S3 bucket {s3_bucket_name}: {e}"
                    )
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            logging.error(f"Error while retrieving CloudTrail trails: {e}")
            report.status = ResourceStatus.FAILED
        return report
