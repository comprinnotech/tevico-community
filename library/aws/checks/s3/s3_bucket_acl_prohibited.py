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


class s3_bucket_acl_prohibited(Check):
    def _get_buckets(self, client):
        try:
            response = client.list_buckets()
            return response.get('Buckets', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_bucket_acl_status(self, client, bucket_name):
        try:
            response = client.get_bucket_ownership_controls(Bucket=bucket_name)
            ownership_controls = response.get('OwnershipControls', {}).get('Rules', [])
            
            # Check if BucketOwnerEnforced is set (ACLs disabled)
            for rule in ownership_controls:
                if rule.get('ObjectOwnership') == 'BucketOwnerEnforced':
                    return bucket_name, True
            return bucket_name, False
        except ClientError as e:
            if e.response['Error']['Code'] == 'OwnershipControlsNotFoundError':
                # If ownership controls are not set, ACLs are enabled
                return bucket_name, False
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

            # Use ThreadPoolExecutor for parallel execution
            with ThreadPoolExecutor(max_workers=31) as executor:
                futures = [
                    executor.submit(self._check_bucket_acl_status, client, bucket.get('Name'))
                    for bucket in buckets if bucket.get('Name')
                ]
                
                for future in futures:
                    try:
                        bucket_name, is_compliant = future.result()
                        if not is_compliant:
                            report.passed = False
                        report.resource_ids_status[bucket_name] = is_compliant
                    except Exception:
                        report.passed = False
                        continue

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['Error checking S3 bucket ACL configuration'] = False

        return report
