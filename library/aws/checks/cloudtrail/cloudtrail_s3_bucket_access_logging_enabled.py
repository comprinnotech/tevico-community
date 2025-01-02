"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudtrail_s3_bucket_access_logging_enabled(Check):
    
    # Get all CloudTrail trails
    def _get_trails(self, cloudtrail_client):
        try:
            response = cloudtrail_client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            return []

    # Check the logging status of an S3 bucket
    def _get_bucket_logging_status(self, s3_client, bucket_name):
        try:
            logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
            return logging_config.get('LoggingEnabled', None) is not None
        except s3_client.exceptions.NoSuchBucket:
            return False
        except (ClientError, BotoCoreError):
            return False

    # Main execution method for running the check
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudtrail_client = connection.client('cloudtrail')
        s3_client = connection.client('s3')
        report.passed = True

        try:
            # Get all CloudTrail trails
            trails = self._get_trails(cloudtrail_client)

            if not trails:
                report.resource_ids_status['NoTrails'] = True
                return report

            # Track unique S3 buckets used by CloudTrail
            cloudtrail_buckets = set()
            
            # Collect all S3 buckets used by CloudTrail trails
            for trail in trails:
                bucket_name = trail.get('S3BucketName')
                if bucket_name:
                    cloudtrail_buckets.add(bucket_name)

            if not cloudtrail_buckets:
                report.passed = False
                return report

            # Check logging status for each CloudTrail S3 bucket
            for bucket_name in cloudtrail_buckets:
                logging_status = self._get_bucket_logging_status(s3_client, bucket_name)
                report.resource_ids_status[bucket_name] = logging_status

                if not logging_status:
                    report.passed = False

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
