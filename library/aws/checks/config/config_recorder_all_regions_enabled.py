"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class config_recorder_all_regions_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize Config client
        client = connection.client('config')

        report = CheckReport(name=__name__)

        # Initialize report status as 'Passed' unless we find a missing recorder or failure state
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Get all regions available to the AWS account
            ec2_client = connection.client('ec2')
            regions = ec2_client.describe_regions()['Regions']
            region_names = [region['RegionName'] for region in regions]

            # Iterate through all regions to check for Config recorder status
            for region in region_names:
                try:
                    # Use a regional Config client
                    regional_client = connection.client('config', region_name=region)

                    # Describe Configuration Recorders in the region
                    response = regional_client.describe_configuration_recorders()
                    recorders = response.get('ConfigurationRecorders', [])

                    if not recorders:
                        # No recorders found
                        report.resource_ids_status[f" {region}: No AWS Config recorders in region."] = False
                        report.passed = False
                    else:
                        # Process each recorder found
                        for recorder in recorders:
                            status_response = regional_client.describe_configuration_recorder_status()
                            recorder_status = status_response.get('ConfigurationRecordersStatus', [])
                            recorder_status_dict = {r['name']: r['recording'] for r in recorder_status}

                            # Check the recorder status
                            if recorder_status_dict.get(recorder['name'], False):
                                report.resource_ids_status[f" {region}: AWS Config recorder {recorder['name']} is enabled."] = True
                            else:
                                report.resource_ids_status[f" {region}: AWS Config recorder {recorder['name']} is disabled."] = False
                                report.passed = False

                            # Check for failure state
                            if recorder_status_dict.get(recorder['name']) == 'FAILURE':
                                report.resource_ids_status[f" {region}: AWS Config recorder {recorder['name']} in failure state."] = False
                                report.passed = False

                except Exception as regional_error:
                    logging.error(f"Error while checking Config recorder in region {region}: {regional_error}")
                    report.resource_ids_status[f" {region}: Error while checking AWS Config: {regional_error}"] = False
                    report.passed = False

        except Exception as e:
            logging.error(f"Error while fetching regions or checking Config recorders: {e}")
            report.passed = False
            report.resource_ids_status = {}

        return report
