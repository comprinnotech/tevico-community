"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class securityhub_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        securityhub_client = connection.client('securityhub')

        regions = connection.client('ec2').describe_regions()['Regions']
        
        for region in regions:
            region_name = region['RegionName']
            regional_securityhub_client = connection.client('securityhub', region_name=region_name)
            
            try:
                hub_status = regional_securityhub_client.describe_hub()
                report.resource_ids_status[region_name] = True
            except regional_securityhub_client.exceptions.ResourceNotFoundException:
                report.resource_ids_status[region_name] = False
            except regional_securityhub_client.exceptions.InvalidAccessException:
                report.resource_ids_status[region_name] = False

        return report

