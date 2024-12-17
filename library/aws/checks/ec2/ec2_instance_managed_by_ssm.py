"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-09
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ec2_instance_managed_by_ssm(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize clients for EC2 and SSM
        ec2_client = connection.client('ec2')
        ssm_client = connection.client('ssm')

        report = CheckReport(name=__name__)
        report.passed = True  # Assume passed unless we find an unmanaged instance
        report.resource_ids_status = {}

        # Fetch all EC2 instances
        try:
            instances_response = ec2_client.describe_instances()
            instances = [i for r in instances_response['Reservations'] for i in r['Instances']]
        except Exception as e:
            report.passed = False
            return report

        # Check each instance
        if not instances:
            report.passed = False
            report.resource_ids_status['No Instances'] = False  # No instances available
            return report

        for instance in instances:
            instance_id = instance['InstanceId']
            report.resource_ids_status[instance_id] = True  # Assume managed initially
            
            # Check the state of the instance
            if instance['State']['Name'] in ["pending", "terminated", "stopped"]:
                report.resource_ids_status[instance_id] = False  # Mark as unmanaged due to state
                report.passed = False
                continue  # Skip to next instance

            # Check if the instance is managed by SSM
            try:
                managed_instances_response = ssm_client.describe_instance_information()
                managed_instances = managed_instances_response['InstanceInformationList']
                managed_instance_ids = {m['InstanceId'] for m in managed_instances}

                if instance_id not in managed_instance_ids:
                    report.passed = False
                    report.resource_ids_status[instance_id] = False  # Mark as unmanaged
            except Exception as e:
                report.passed = False
                report.resource_ids_status[instance_id] = False
                
        return report
