"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
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
        report.passed = True
        client = connection.client('cloudtrail')

        try:
            trails = self._get_trails(client)

            if not trails:
                report.passed = False
                return report

            for trail in trails:
                try:
                    trail_name, has_cloudwatch_logging = self._check_cloudwatch_logging(trail)
                    report.resource_ids_status[trail_name] = has_cloudwatch_logging

                    if not has_cloudwatch_logging:
                        report.passed = False

                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
