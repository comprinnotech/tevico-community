"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""

import boto3
import json
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from concurrent.futures import ThreadPoolExecutor


class s3_bucket_secure_transport_policy(Check):
    def _get_buckets(self, client):
        """Get list of S3 buckets"""
        try:
            response = client.list_buckets()
            return response.get('Buckets', [])
        except (ClientError, BotoCoreError):
            return []

    def _is_secure_transport_statement(self, statement):
        """Check if statement enforces secure transport"""
        try:
            if statement.get('Effect') != 'Deny':
                return False

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            condition = statement.get('Condition', {})
            bool_condition = condition.get('Bool', {})
            secure_transport = bool_condition.get('aws:SecureTransport')

            # Check if the statement denies non-HTTPS access for any S3 actions
            return (secure_transport == 'false' and 
                   ('s3:*' in actions or '*' in actions))
                   
        except Exception:
            return False

    def _check_bucket_policy(self, client, bucket_name):
        """Check individual bucket policy"""
        try:
            response = client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response.get('Policy', '{}'))
            statements = policy.get('Statement', [])
            
            return bucket_name, any(self._is_secure_transport_statement(s) for s in statements)
            
        except ClientError:
            return bucket_name, False
        except Exception:
            return bucket_name, False

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Execute the check"""
        report = CheckReport(name=__name__)
        report.passed = False
        
        try:
            client = connection.client('s3')
            buckets = self._get_buckets(client)

            if not buckets:
                report.resource_ids_status['No S3 buckets found'] = False
                return report

            with ThreadPoolExecutor(max_workers=31) as executor:
                futures = [
                    executor.submit(self._check_bucket_policy, client, bucket.get('Name'))
                    for bucket in buckets if bucket.get('Name')
                ]

                compliant_buckets = 0
                total_buckets = len(buckets)
                
                for future in futures:
                    try:
                        bucket_name, has_secure_transport = future.result()
                        report.resource_ids_status[bucket_name] = has_secure_transport
                        if has_secure_transport:
                            compliant_buckets += 1
                   
                    except Exception:
                        continue

                report.passed = compliant_buckets == total_buckets

        except Exception:
            report.resource_ids_status['Error checking bucket policies'] = False

        return report
