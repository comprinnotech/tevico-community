"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class config_recorder_all_regions_enabled(Check):
    def _get_regions(self, ec2_client):
        """Get list of all enabled regions."""
        try:
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response.get('Regions', [])]
        except (ClientError, BotoCoreError):
            
            return []

    def _check_config_recorder_status(self, config_client, region):
        """Check Config recorder status for a specific region."""
        try:
            # Check if configuration recorder exists
            recorders_response = config_client.describe_configuration_recorders()
            if not recorders_response.get('ConfigurationRecorders', []):
                return False

            # Check recorder status
            status_response = config_client.describe_configuration_recorder_status()
            recorder_statuses = status_response.get('ConfigurationRecordersStatus', [])
            
            if not recorder_statuses:
                return False

            # Check if all recorders are enabled and recording
            return all(
                status.get('recording', False) and 
                status.get('lastStatus', '') == 'SUCCESS'
                for status in recorder_statuses
            )

        except (ClientError, BotoCoreError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if any check fails
        
        try:
            ec2_client = connection.client('ec2')
            regions = self._get_regions(ec2_client)

            if not regions:
                report.resource_ids_status['No regions found'] = False
                report.passed = False
                return report

            for region in regions:
                try:
                    config_client = connection.client('config', region_name=region)
                    status = self._check_config_recorder_status(config_client, region)
                    report.resource_ids_status[region] = status
                    if not status:
                        report.passed = False
                except (ClientError, BotoCoreError):
                    report.resource_ids_status[region] = False
                    report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error checking Config recorder status'] = False
            report.passed = False

        return report
