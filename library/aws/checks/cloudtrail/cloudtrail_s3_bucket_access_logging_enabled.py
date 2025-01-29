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
        cloudtrail_client = connection.client('cloudtrail')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            trail_info = cloudtrail_client.describe_trails()
            if not trail_info['trailList']:
                logging.info("No CloudTrails found")
                return report

            for trail in trail_info['trailList']:
                trail_name = trail.get('Name')
                s3_bucket_name = trail.get('S3BucketName')
                is_org_trail = trail.get('IsOrganizationTrail', False)

                if not s3_bucket_name:
                    report.resource_ids_status[f"CloudTrail {trail_name} - No S3 bucket configured"] = True
                    continue

                # Check if it's an organization trail and we're in a member account
                if is_org_trail:
                    # Get the trail status to verify if it's actively logging
                    trail_status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                    is_logging = trail_status.get('IsLogging', False)

                    if is_logging:
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - Organization trail, S3 bucket {s3_bucket_name} "
                            f"access logging should be verified in management account"
                        ] = True
                        logging.info(
                            f"CloudTrail {trail_name} is an organization trail. "
                            f"S3 bucket {s3_bucket_name} access logging should be verified "
                            "in the management account or delegated administrator account."
                        )
                        continue
                    else:
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - Organization trail is not logging"
                        ] = False
                        continue

                # For non-organization trails or if bucket is in same account, 
                # proceed with original bucket logging check
                try:
                    bucket_location = connection.client('s3').get_bucket_location(
                        Bucket=s3_bucket_name
                    )
                    bucket_region = bucket_location.get('LocationConstraint')
                    s3_client = connection.client('s3', region_name=bucket_region)
                    
                    logging_config = s3_client.get_bucket_logging(Bucket=s3_bucket_name)
                    logging_enabled = logging_config.get('LoggingEnabled', None)

                    if logging_enabled:
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} "
                            "Access Logging: Enabled"
                        ] = True
                    else:
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} "
                            "Access Logging: Disabled"
                        ] = False

                except Exception as e:
                    if "Access Denied" in str(e):
                        logging.info(
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} "
                            "is in a different account. Skipping bucket logging check."
                        )
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} "
                            "is in a different account. Please verify access logging "
                            "in the bucket owner's account."
                        ] = True
                    else:
                        logging.info(
                            f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} "
                            "is in a different account. Skipping bucket logging check."
                        )
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[
                            f"CloudTrail {trail_name} - Error checking S3 bucket "
                            f"{s3_bucket_name}: {str(e)}"
                        ] = False

        except Exception as e:
            logging.error(f"Error while retrieving CloudTrail trails: {e}")
            report.status = ResourceStatus.FAILED
        
        return report
