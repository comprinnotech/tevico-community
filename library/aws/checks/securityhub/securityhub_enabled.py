"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from concurrent.futures import ThreadPoolExecutor


class securityhub_enabled(Check):
    def _get_regions(self, ec2_client):
        try:
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response.get('Regions', [])]
        except (ClientError, BotoCoreError):
            return []

    def _check_securityhub_status(self, client):
        try:
            # Check if Security Hub is enabled
            client.describe_hub()
            
            # Check standard subscriptions
            standards_response = client.get_enabled_standards()
            if not standards_response.get('StandardsSubscriptions'):
                return False
            
            # Check if all standards are READY
            for standard in standards_response['StandardsSubscriptions']:
                if standard.get('StandardsStatus') != 'READY':
                    return False
            
            return True
        except (ClientError, BotoCoreError):
            return False

    def _check_region(self, connection, region):
        try:
            regional_client = connection.client('securityhub', region_name=region)
            status = self._check_securityhub_status(regional_client)
            return region, status
        except (ClientError, BotoCoreError):
            return region, False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if any region fails
        
        try:
            ec2_client = connection.client('ec2')
            regions = self._get_regions(ec2_client)

            if not regions:
                report.passed = False
                report.resource_ids_status['No regions found'] = False
                return report

            # Use ThreadPoolExecutor for parallel execution
            with ThreadPoolExecutor(max_workers=31) as executor:
                future_to_region = {
                    executor.submit(self._check_region, connection, region): region 
                    for region in regions
                }
                
                for future in future_to_region:
                    try:
                        region, status = future.result()
                        if not status:
                            report.passed = False
                        report.resource_ids_status[region] = status
                    except Exception:
                        region = future_to_region[future]
                        report.passed = False
                        report.resource_ids_status[region] = False

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['Error checking SecurityHub configuration'] = False

        return report
