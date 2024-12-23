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
    # Helper method to fetch the list of all S3 buckets
    def _get_buckets(self, client):
        # Retrieves the list of S3 buckets in the account
        response = client.list_buckets()
        return response.get('Buckets', [])

    # Helper method to check if access logging is enabled for a specific S3 bucket
    def _get_bucket_logging_status(self, client, bucket_name):
        try:
            # Fetch the logging configuration of the bucket
            logging_config = client.get_bucket_logging(Bucket=bucket_name)
            # Check if the 'LoggingEnabled' key exists in the configuration
            return logging_config.get('LoggingEnabled', None) is not None
        except client.exceptions.NoSuchBucket:
            # Return False if the bucket does not exist
            return False
        except (ClientError, BotoCoreError):
            # Handle other API or SDK errors gracefully
            return False

    # Main method to execute the check for S3 bucket access logging
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('s3')
        report.passed = True  # Assume all buckets have logging enabled unless proven otherwise

        try:
            # Fetch the list of S3 buckets
            buckets = self._get_buckets(client)

            if not buckets:  # If no buckets exist, mark the check as failed
                report.passed = False
                return report

            for bucket in buckets:
                try:
                    # Get the name of the bucket
                    bucket_name = bucket['Name']
                    # Check if logging is enabled for the bucket
                    logging_status = self._get_bucket_logging_status(client, bucket_name)

                    if logging_status:
                        # If logging is enabled, record a positive status
                        report.resource_ids_status[bucket_name] = True
                    else:
                        # If logging is disabled, record a negative status and mark the report as failed
                        report.passed = False
                        report.resource_ids_status[bucket_name] = False

                except KeyError:
                    # Handle cases where expected keys are missing in the bucket metadata
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other unexpected exceptions
            report.passed = False
            return report

        return report
