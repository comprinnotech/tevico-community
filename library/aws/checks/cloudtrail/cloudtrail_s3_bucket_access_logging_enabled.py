"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudtrail_s3_bucket_access_logging_enabled(Check):
    
    def _get_trails(self, cloudtrail_client):
        try:
            response = cloudtrail_client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            return []

    def _get_bucket_logging_status(self, s3_client, bucket_name):
        try:
            # Check if bucket exists and is accessible
            s3_client.head_bucket(Bucket=bucket_name)
            return True
        except s3_client.exceptions.NoSuchBucket:
            return False
        except (ClientError, BotoCoreError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudtrail_client = connection.client('cloudtrail')
        s3_client = connection.client('s3')
        report.passed = False  # Start with failed assumption

        try:
            # Get all CloudTrail trails
            trails = self._get_trails(cloudtrail_client)

            if not trails:
                report.resource_ids_status['NoTrails'] = False
                return report

            # Check each trail's S3 bucket
            for trail in trails:
                bucket_name = trail.get('S3BucketName')
                if not bucket_name:
                    report.resource_ids_status[trail.get('Name', 'Unknown')] = False
                    continue

                # Verify bucket exists and is accessible
                bucket_exists = self._get_bucket_logging_status(s3_client, bucket_name)
                report.resource_ids_status[bucket_name] = bucket_exists

                if bucket_exists:
                    report.passed = True  # Pass if at least one trail has a valid S3 bucket

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report

