"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from concurrent.futures import ThreadPoolExecutor


class s3_bucket_object_versioning(Check):
    def _get_buckets(self, client):
        try:
            response = client.list_buckets()
            return response.get('Buckets', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_bucket_versioning(self, client, bucket_name):
        try:
            versioning = client.get_bucket_versioning(Bucket=bucket_name)
            # Explicitly check for 'Enabled' status
            is_enabled = versioning.get('Status') == 'Enabled'
            return bucket_name, is_enabled
        except (ClientError, BotoCoreError):
            return bucket_name, False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if any bucket fails
        
        try:
            client = connection.client('s3')
            buckets = self._get_buckets(client)

            if not buckets:
                report.passed = False
                report.resource_ids_status['No S3 buckets found'] = False
                return report

            # Use ThreadPoolExecutor for parallel execution
            with ThreadPoolExecutor(max_workers=31) as executor:
                futures = [
                    executor.submit(self._check_bucket_versioning, client, bucket.get('Name'))
                    for bucket in buckets if bucket.get('Name')
                ]
                
                for future in futures:
                    try:
                        bucket_name, is_versioned = future.result()
                        if not is_versioned:
                            report.passed = False
                        report.resource_ids_status[bucket_name] = is_versioned
                    except Exception:
                        report.passed = False
                        continue

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['Error checking S3 bucket versioning configuration'] = False

        return report

