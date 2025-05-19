"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class cloudtrail_s3_bucket_access_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        cloudtrail_client = connection.client('cloudtrail')
        s3_client = connection.client('s3')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            
            trails = []
            next_token = None

            while True:
                response = cloudtrail_client.describe_trails(includeShadowTrails=False, NextToken=next_token) if next_token else cloudtrail_client.describe_trails(includeShadowTrails=False)
                trails.extend(response.get('trailList', []))
                next_token = response.get('NextToken')
                
                if not next_token:
                    break

            if not trails:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No CloudTrail trails found."
                    )
                )
                return report  # Early exit since there are no trails to check
            
            
            
            
            # trail_info = cloudtrail_client.describe_trails()
            # if not trail_info['trailList']:
            #     return report  # No CloudTrails found, nothing to check.

            for trail in trails:
                trail_name = trail.get('Name')
                trail_arn = trail.get('TrailARN')
                s3_bucket_name = trail.get('S3BucketName')
                is_org_trail = trail.get('IsOrganizationTrail', False)

                if not s3_bucket_name:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=trail_arn),
                            status=CheckStatus.PASSED,
                            summary=f"CloudTrail {trail_name} - No S3 bucket configured."
                        )
                    )
                    continue


                # Get the bucket's region
                try:
                    bucket_location = s3_client.get_bucket_location(Bucket=s3_bucket_name)
                    bucket_region = bucket_location.get('LocationConstraint', 'us-east-1')  # Default to us-east-1
                    s3_client_regional = connection.client('s3', region_name=bucket_region)
                except (BotoCoreError, ClientError) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=trail_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"CloudTrail {trail_name} - Error retrieving S3 bucket location.",
                            exception=str(e)
                        )
                    )
                    continue

                # Check if access logging is enabled on the bucket
                try:
                    logging_config = s3_client_regional.get_bucket_logging(Bucket=s3_bucket_name)
                    logging_enabled = logging_config.get('LoggingEnabled', None)

                    if logging_enabled:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=trail_arn),
                                status=CheckStatus.PASSED,
                                summary=f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} access logging is ENABLED."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=trail_arn),
                                status=CheckStatus.FAILED,
                                summary=f"CloudTrail {trail_name} - S3 bucket {s3_bucket_name} access logging is DISABLED."
                            )
                        )

                except ClientError as e:
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=trail_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"CloudTrail {trail_name} - Error checking S3 bucket logging.",
                                exception=str(e)
                            )
                        )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving CloudTrail trails.",
                    exception=str(e)
                )
            )

        return report
