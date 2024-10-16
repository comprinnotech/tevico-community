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
        report = CheckReport(name=__name__)
        ec2_client = connection.client('ec2')
        ssm_client = connection.client('ssm')
        instances = ec2_client.describe_instances()['Reservations']
        report.passed = True 
        ssm_managed_instances = ssm_client.describe_instance_information()['InstanceInformationList']
        ssm_instance_ids = {instance['InstanceId'] for instance in ssm_managed_instances}
        for reservation in instances:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                if instance['State']['Name'] not in ["pending", "terminated", "stopped"]: #Ignore instanes that are not running
                    if instance_id not in ssm_instance_ids:
                        report.passed = False
                        report.resource_ids_status[instance_id] = False
                    else:
                        report.resource_ids_status[instance_id] = True
        return report
        