"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudtrail_cloudwatch_logging_enabled(Check):
    def _get_trails(self, client):
        try:
            response = client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_cloudwatch_logging(self, trail):
        trail_name = trail['Name']
        cloudwatch_logs_arn = trail.get('CloudWatchLogsLogGroupArn')
        return trail_name, bool(cloudwatch_logs_arn)

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = False  # Start with False for security-first approach
        client = connection.client('cloudtrail')

        try:
            trails = self._get_trails(client)

            if not trails:
                report.resource_ids_status['NoTrails'] = False
                return report

            # Track if at least one trail has CloudWatch logging enabled
            has_logging_enabled = False

            for trail in trails:
                try:
                    trail_name, has_cloudwatch_logging = self._check_cloudwatch_logging(trail)
                    report.resource_ids_status[trail_name] = has_cloudwatch_logging

                    if has_cloudwatch_logging:
                        has_logging_enabled = True

                except KeyError:
                    report.resource_ids_status[trail.get('Name', 'Unknown')] = False

            # Set final status based on having at least one trail with logging
            report.passed = has_logging_enabled

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report

