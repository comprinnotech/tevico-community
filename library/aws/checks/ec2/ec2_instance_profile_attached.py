"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check


class ec2_instance_profile_attached(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.passed = True  # Start assuming all instances have profiles

        try:
            # Fetch all EC2 instances
            response = ec2_client.describe_instances()
            reservations = response.get('Reservations', [])
        except Exception as e:
            report.passed = False
            #report.message = f"Error fetching EC2 instances: {str(e)}"
            return report

        if not reservations:
            report.passed = False
            #report.message = "No EC2 instances found."
            return report

        for reservation in reservations:
            for instance in reservation.get('Instances', []):
                instance_id = instance.get('InstanceId')
                instance_profile = instance.get('IamInstanceProfile', None)

                if instance_profile:
                    report.resource_ids_status[instance_id] = True  # Instance has a profile attached
                else:
                    report.passed = False
                    report.resource_ids_status[instance_id] = False  # No profile attached
                    #report.message = f"EC2 Instance {instance_id} does not have an IAM instance profile attached."

        return report