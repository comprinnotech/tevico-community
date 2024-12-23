"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudtrail_enabled(Check):
    # Helper method to fetch the list of CloudTrail trails
    def _get_trails(self, client):
        # Fetches the list of CloudTrail trails using the AWS CloudTrail API
        response = client.describe_trails()
        return response.get('trailList', [])

    # Helper method to check if logging is enabled for a specific trail
    def _is_logging_enabled(self, client, trail_name):
        try:
            # Fetches the status of the trail to determine if logging is enabled
            response = client.get_trail_status(Name=trail_name)
            return response.get('IsLogging', False)
        except client.exceptions.TrailNotFoundException:
            # If the trail is not found, logging is considered disabled
            return False
        except (ClientError, BotoCoreError):
            # Handle any API or SDK errors by considering logging disabled
            return False

    # Helper method to check both logging status and multi-region configuration of a trail
    def _check_trail_status(self, client, trail):
        trail_name = trail['Name']
        # Check if logging is enabled for the trail
        is_logging = self._is_logging_enabled(client, trail_name)
        # Check if the trail is configured as a multi-region trail
        is_multi_region = trail.get('IsMultiRegionTrail', False)
        # Returns the trail name and whether both conditions are met
        return trail_name, is_logging and is_multi_region

    # Main method to execute the check for CloudTrail configuration
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudtrail')
        report = CheckReport(name=__name__)
        report.passed = True  # Assume success unless a failure is detected

        try:
            # Fetch all CloudTrail trails
            trails = self._get_trails(client)

            if not trails:  # If no trails exist, mark the report as failed
                report.passed = False
                return report

            for trail in trails:
                try:
                    # Check the logging and multi-region status for the current trail
                    trail_name, trail_status = self._check_trail_status(client, trail)
                    report.resource_ids_status[trail_name] = trail_status

                    # If either condition is not met, update the report status
                    if not trail_status:
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
