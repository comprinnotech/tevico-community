"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudtrail_multiregion_enabled(Check):
    
    # Retrieve the list of CloudTrail trails for the account
    def _get_trails(self, client):
        try:
            response = client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            return []

    # Check if multi-region is enabled for a specific trail
    def _check_multiregion_enabled(self, trail):
        trail_name = trail['Name']
        is_multiregion = trail.get('IsMultiRegionTrail', False)
        return trail_name, is_multiregion

    # Main execution method for running the check
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        client = connection.client('cloudtrail')

        try:
            # Fetch all trails from the CloudTrail service
            trails = self._get_trails(client)

            # If no trails are found, mark the check as failed
            if not trails:
                report.passed = False
                return report

            # Iterate over each trail and check if multi-region is enabled
            for trail in trails:
                try:
                    trail_name, is_multiregion = self._check_multiregion_enabled(trail)
                    report.resource_ids_status[trail_name] = is_multiregion

                    # If multi-region is not enabled for any trail, mark the check as failed
                    if not is_multiregion:
                        report.passed = False

                except KeyError:
                    # If there's a KeyError, mark the check as failed and stop further processing
                    report.passed = False
                    return report

        # Catch all exceptions related to CloudTrail and boto3 operations
        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        # Return the final check report with the result
        return report
