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


class s3_bucket_default_encryption(Check):
    def _get_buckets(self, client):
        try:
            response = client.list_buckets()
            return response.get('Buckets', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_bucket_encryption(self, client, bucket_name):
        try:
            # Check if bucket has default encryption enabled
            encryption = client.get_bucket_encryption(Bucket=bucket_name)
            encryption_rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if encryption_rules:
                return bucket_name, True  # Default encryption enabled
                
            # If no encryption config found, check bucket policy
            try:
                policy = client.get_bucket_policy(Bucket=bucket_name)
                # Checking bucket policy for encryption enforcement is not implemented here
                return bucket_name, False  # Default encryption not found, policy check here
            except ClientError:
                return bucket_name, False  # No policy found
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return bucket_name, False  # Encryption not found
            return bucket_name, False
        except BotoCoreError:
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

            # Use ThreadPoolExecutor for parallel execution of encryption checks on buckets
            with ThreadPoolExecutor(max_workers=31) as executor:
                futures = [
                    executor.submit(self._check_bucket_encryption, client, bucket.get('Name'))
                    for bucket in buckets if bucket.get('Name')
                ]
                
                for future in futures:
                    try:
                        bucket_name, is_encrypted = future.result()
                        if not is_encrypted:
                            report.passed = False
                        report.resource_ids_status[bucket_name] = is_encrypted
                    except Exception:
                        report.passed = False
                        continue

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['Error checking S3 bucket encryption configuration'] = False

        return report
