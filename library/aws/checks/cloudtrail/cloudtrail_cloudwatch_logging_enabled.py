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
    # Helper method to fetch the list of CloudTrail trails
    def _get_trails(self, client):
        try:
            # Fetches the list of CloudTrail trails
            response = client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            # Returns an empty list if there is an error while fetching trails
            return []

    # Helper method to check if CloudWatch logging is enabled for a trail
    def _check_cloudwatch_logging(self, trail):
        trail_name = trail['Name']
        # Check for the presence of the CloudWatch Logs Log Group ARN
        cloudwatch_logs_arn = trail.get('CloudWatchLogsLogGroupArn')
        return trail_name, bool(cloudwatch_logs_arn)

    # Main method to execute the check for CloudWatch logging
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Assume success unless a failure is detected
        client = connection.client('cloudtrail')

        try:
            # Fetch all CloudTrail trails
            trails = self._get_trails(client)

            if not trails:  # If no trails exist, mark the report as failed
                report.passed = False
                return report

            for trail in trails:
                try:
                    # Check if CloudWatch logging is enabled for the current trail
                    trail_name, has_cloudwatch_logging = self._check_cloudwatch_logging(trail)
                    report.resource_ids_status[trail_name] = has_cloudwatch_logging

                    # If logging is not enabled, update the report status
                    if not has_cloudwatch_logging:
                        report.passed = False

                except KeyError:
                    # Handle cases where expected keys are missing in the trail configuration
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report
