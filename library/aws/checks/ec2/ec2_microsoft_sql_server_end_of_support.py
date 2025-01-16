"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-11
"""

import boto3
from datetime import datetime
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class ec2_microsoft_sql_server_end_of_support(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED  # Initialize as passed
        client = connection.client('ec2')

        # Step 1: Get all EC2 instances
        instances = client.describe_instances()['Reservations']

        # Step 2: Iterate over each instance
        for reservation in instances:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                ami_id = instance['ImageId']
                
                # Skip non-Windows or non-running instances
                if instance['State']['Name'] != 'running':
                    continue
                if instance.get('Platform') != 'windows':
                    continue

                # Step 3: Get AMI details
                ami_details = client.describe_images(ImageIds=[ami_id])['Images'][0]
                ami_name = ami_details['Name']
                ami_description = ami_details.get('Description', '')

                # Step 4: Determine if the AMI relates to Microsoft SQL Server
                if not ("sql" in ami_name.lower() or "sql server" in ami_description.lower()):
                    report.resource_ids_status[instance_id] = True
                    continue

                # Extract the SQL Server version from the AMI name or description
                sql_version = self._extract_sql_version(ami_name, ami_description)
                if not sql_version:
                    continue

                # Calculate end-of-support date and compare with today's date
                eos_date = self._calculate_end_of_support(sql_version)
                if eos_date and eos_date < datetime.now():
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[instance_id] = False
                else:
                    report.resource_ids_status[instance_id] = True

        return report

    def _extract_sql_version(self, ami_name: str, ami_description: str) -> str:
        """
        Extracts the SQL Server version from the AMI name or description.
        Assumes the version is indicated as a year (e.g., 2012, 2014, 2016, etc.).
        """
        for version in ["2012", "2014", "2016", "2017", "2019", "2022"]:  # All versions
            if version in ami_name or version in ami_description:
                return version
        return None

    def _calculate_end_of_support(self, sql_version: str) -> datetime:
        """
        Calculates the end-of-support date based on the SQL Server version.
        The end-of-support date is fixed for each version.
        """
        end_of_support = {
            "2012": datetime(2022, 7, 12),
            "2014": datetime(2024, 7, 9),
            "2016": datetime(2026, 7, 14),
            "2017": datetime(2027, 10, 12),
            "2019": datetime(2030, 1, 9),
            "2022": datetime(2033, 1, 12),
        }

        # Get the end-of-support date for the specified version
        return end_of_support.get(sql_version)
