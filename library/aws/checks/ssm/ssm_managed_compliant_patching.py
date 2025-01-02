"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ssm_managed_compliant_patching(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            ec2_client = connection.client('ec2')
            ssm_client = connection.client('ssm')

            # Get all running EC2 instances
            response = ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )

            instance_ids = [
                instance['InstanceId'] 
                for reservation in response.get('Reservations', [])
                for instance in reservation.get('Instances', [])
            ]

            if not instance_ids:
                report.resource_ids_status['No running instances found'] = False
                report.passed = False
                return report

            try:
                # Get patch states for all instances
                patch_response = ssm_client.describe_instance_patch_states(
                    InstanceIds=instance_ids
                )
                patch_states = patch_response.get('InstancePatchStates', [])

                if not patch_states:
                    report.resource_ids_status['No patch states found'] = False
                    report.passed = False
                    return report

                # Check compliance status for each instance
                for state in patch_states:
                    instance_id = state['InstanceId']
                    is_compliant = state['PatchComplianceStatus'] == "COMPLIANT"
                    report.resource_ids_status[instance_id] = is_compliant

                # Check passes only if all instances are compliant
                report.passed = all(report.resource_ids_status.values())

            except (ClientError, BotoCoreError):
                report.resource_ids_status['Error checking patch states'] = False
                report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error checking instances'] = False
            report.passed = False

        return report

