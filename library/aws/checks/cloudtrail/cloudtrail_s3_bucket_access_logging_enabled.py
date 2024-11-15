"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudtrail_s3_bucket_access_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('s3')
        response = client.list_buckets()

        buckets = response.get('Buckets', [])
        if not buckets:
            report.passed = False
            return report

        for bucket in buckets:
            bucket_name = bucket['Name']
            logging_status = self.get_bucket_logging_status(client, bucket_name)

            if logging_status:
                report.resource_ids_status[bucket_name] = True
            else:
                report.passed = False
                report.resource_ids_status[bucket_name] = False

        return report

    def get_bucket_logging_status(self, client, bucket_name):
        try:
            logging_config = client.get_bucket_logging(Bucket=bucket_name)
            return logging_config.get('LoggingEnabled', None) is not None
        except client.exceptions.NoSuchBucket:
            return False
