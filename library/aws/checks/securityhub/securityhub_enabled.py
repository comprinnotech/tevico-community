"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from concurrent.futures import ThreadPoolExecutor


class securityhub_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ec2_client = connection.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

        def check_region(region_name):
            try:
                regional_securityhub_client = connection.client('securityhub', region_name=region_name)
                regional_securityhub_client.describe_hub()
                return region_name, True
            except (regional_securityhub_client.exceptions.ResourceNotFoundException,
                    regional_securityhub_client.exceptions.InvalidAccessException):
                return region_name, False

        max_threads = 31  
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = list(executor.map(check_region, regions))

        report.resource_ids_status = {region: status for region, status in results}
        return report

