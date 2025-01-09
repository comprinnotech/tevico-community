"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ssm_patch_manager_enabled(Check):
    def _get_instances(self, ec2_client):
        try:
            response = ec2_client.describe_instances()
            instances = [
                instance['InstanceId']
                for reservation in response.get('Reservations', [])
                for instance in reservation.get('Instances', [])
            ]
            return instances
        except (ClientError, BotoCoreError):
            return []

    def _check_patch_manager_status(self, ssm_client, instance_id):
        try:
            response = ssm_client.describe_instance_patch_states(
                InstanceIds=[instance_id]
            )
            return bool(response.get('InstancePatchStates', []))
        except (ClientError, BotoCoreError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if any check fails
        
        try:
            ec2_client = connection.client('ec2')
            ssm_client = connection.client('ssm')

            instance_ids = self._get_instances(ec2_client)

            if not instance_ids:
                report.resource_ids_status['No instances found'] = False
                report.passed = False
                return report

            for instance_id in instance_ids:
                status = self._check_patch_manager_status(ssm_client, instance_id)
                report.resource_ids_status[instance_id] = status
                if not status:
                    report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error checking Patch Manager status'] = False
            report.passed = False

        return report
