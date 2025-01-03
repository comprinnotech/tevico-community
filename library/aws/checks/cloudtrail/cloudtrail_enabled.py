"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudtrail_enabled(Check):
    def _get_trails(self, client):
        response = client.describe_trails()
        return response.get('trailList', [])

    def _is_logging_enabled(self, client, trail_name):
        try:
            response = client.get_trail_status(Name=trail_name)
            return response.get('IsLogging', False)
        except client.exceptions.TrailNotFoundException:
            return False
        except (ClientError, BotoCoreError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudtrail')
        report = CheckReport(name=__name__)
        report.passed = True  # Start with passed assumption, will fail if any check fails

        try:
            trails = self._get_trails(client)

            if not trails:  # If no trails exist, mark the report as failed
                report.passed = False
                report.resource_ids_status['NoTrails'] = False  # Added this line
                return report

            for trail in trails:
                try:
                    trail_name = trail['Name']
                    # Check if logging is enabled
                    is_logging = self._is_logging_enabled(client, trail_name)
                    report.resource_ids_status[trail_name] = is_logging

                    if not is_logging:
                        report.passed = False  # Fail if any trail has logging disabled

                except KeyError:
                    # If trail name is missing, mark as failed
                    report.passed = False
                    report.resource_ids_status['NoTrails'] = False  # Added for KeyError case
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['NoTrails'] = False  # Added for exception case
            return report

        return report
