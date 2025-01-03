"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudtrail_multiregion_enabled(Check):
    
    def _get_trails(self, client):
        try:
            response = client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_multiregion_enabled(self, trail):
        trail_name = trail['Name']
        is_multiregion = trail.get('IsMultiRegionTrail', False)
        return trail_name, is_multiregion

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = False  # Start with False for security-first approach
        client = connection.client('cloudtrail')

        try:
            trails = self._get_trails(client)

            if not trails:
                report.resource_ids_status['NoTrails'] = False
                return report

            # Track if at least one multi-region trail exists
            has_multiregion_trail = False

            for trail in trails:
                try:
                    trail_name, is_multiregion = self._check_multiregion_enabled(trail)
                    report.resource_ids_status[trail_name] = is_multiregion

                    if is_multiregion:
                        has_multiregion_trail = True

                except KeyError:
                    report.resource_ids_status[trail.get('Name', 'Unknown')] = False

            # Set final status based on having at least one multi-region trail
            report.passed = has_multiregion_trail

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report
