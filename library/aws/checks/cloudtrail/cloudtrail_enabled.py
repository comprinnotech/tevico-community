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

    def _check_trail_status(self, client, trail):
        trail_name = trail['Name']
        is_logging = self._is_logging_enabled(client, trail_name)
        is_multi_region = trail.get('IsMultiRegionTrail', False)
        return trail_name, is_logging and is_multi_region

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudtrail')
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            trails = self._get_trails(client)

            if not trails:
                report.passed = False
                return report

            for trail in trails:
                try:
                    trail_name, trail_status = self._check_trail_status(client, trail)
                    report.resource_ids_status[trail_name] = trail_status

                    if not trail_status:
                        report.passed = False

                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
