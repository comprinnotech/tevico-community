"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudtrail_multiregion_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        cloudtrail_client = connection.client('cloudtrail')
        response = cloudtrail_client.describe_trails()

        trails = response.get('trailList', [])
        if not trails:
            report.passed = False
            return report

        for trail in trails:
            trail_name = trail['Name']
            is_multiregion = trail.get('IsMultiRegionTrail', False)

            if is_multiregion:
                report.resource_ids_status[trail_name] = True
            else:
                report.passed = False
                report.resource_ids_status[trail_name] = False

        return report

