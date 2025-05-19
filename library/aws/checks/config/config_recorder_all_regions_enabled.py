"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-03-21
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class config_recorder_all_regions_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Executes the check to verify if AWS Config recorders are enabled in all available regions.
        
        Args:
            connection (boto3.Session): A valid AWS session object.

        Returns:
            CheckReport: Report detailing regions where AWS Config is enabled or missing.
        """

        # Initialize the check report object
        report = CheckReport(name=__name__)
        report.resource_ids_status = []  # Stores the status of AWS Config recorders per region

        try:
            # Create EC2 client to fetch the list of all AWS regions
            ec2_client = connection.client('ec2')

            # Fetch all available AWS regions
            response = ec2_client.describe_regions()
            all_regions = [region['RegionName'] for region in response['Regions']]
            
            # Lists to store regions where AWS Config is enabled or missing
            enabled_regions = []
            missing_regions = []

            # Iterate over all AWS regions to check AWS Config recorder status
            for region in all_regions:
                try:
                    # Create an AWS Config client for the specific region
                    regional_client = connection.client('config', region_name=region)

                    # Fetch the configuration recorders in the region
                    response = regional_client.describe_configuration_recorders()
                    recorders = response.get('ConfigurationRecorders', [])

                    if recorders:
                        # If recorders are found, add the region to enabled list
                        enabled_regions.append(region)
                    else:
                        # If no recorders are found, add the region to missing list
                        missing_regions.append(region)

                except (BotoCoreError, ClientError) as e:
                    # Handle AWS API errors (e.g., permission issues, network failures)
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=region),
                            status=CheckStatus.UNKNOWN,  # Status unknown due to error
                            summary=f"Failed to check AWS Config recorder status in region {region}.",
                            exception=str(e)  # Store exception details
                        )
                    )

            # If there are regions without AWS Config enabled, mark them as FAILED
            if missing_regions:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="AWS Config"),
                        status=CheckStatus.FAILED,
                        summary=f"AWS Config recorder is not enabled in the following regions: {', '.join(missing_regions)}."
                    )
                )

            # If there are regions with AWS Config enabled, mark them as PASSED
            if enabled_regions:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="AWS Config"),
                        status=CheckStatus.PASSED,
                        summary=f"AWS Config recorder is enabled in the following regions: {', '.join(enabled_regions)}."
                    )
                )

        except (BotoCoreError, ClientError) as e:
            # Handle AWS API errors when retrieving regions
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS Regions"),
                    status=CheckStatus.UNKNOWN,  # Status unknown due to error
                    summary="Failed to retrieve the list of AWS regions.",
                    exception=str(e)  # Store exception details
                )
            )
        except Exception as e:
            # Catch other unexpected errors and report them as UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS Config"),
                    status=CheckStatus.UNKNOWN,  # General failure status
                    summary="Unexpected error occurred while retrieving the list of AWS regions.",
                    exception=str(e)  # Store exception details
                )
            )


        return report  # Return the final report with all region statuses
