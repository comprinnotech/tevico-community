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
    def _get_buckets(self, client):
        response = client.list_buckets()
        return response.get('Buckets', [])

    def _get_bucket_logging_status(self, client, bucket_name):
        try:
            logging_config = client.get_bucket_logging(Bucket=bucket_name)
            return logging_config.get('LoggingEnabled', None) is not None
        except client.exceptions.NoSuchBucket:
            return False
        except (ClientError, BotoCoreError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('s3')
        report.passed = True

        try:
            buckets = self._get_buckets(client)

            if not buckets:
                report.passed = False
                return report

            for bucket in buckets:
                try:
                    bucket_name = bucket['Name']
                    logging_status = self._get_bucket_logging_status(client, bucket_name)

                    if logging_status:
                        report.resource_ids_status[bucket_name] = True
                    else:
                        report.passed = False
                        report.resource_ids_status[bucket_name] = False

                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
