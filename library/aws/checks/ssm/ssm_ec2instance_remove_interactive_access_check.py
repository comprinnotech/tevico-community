"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ssm_ec2instance_remove_interactive_access_check(Check):
    def _get_instances(self, ec2_client):
        try:
            response = ec2_client.describe_instances()
            return response.get('Reservations', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_interactive_access(self, ssm_client, instance_id):
        try:
            # Check if instance is SSM managed
            ssm_instance_info = ssm_client.describe_instance_information(
                Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
            )

            if not ssm_instance_info.get('InstanceInformationList'):
                return False

            # Check for interactive shell script associations
            session_access_info = ssm_client.list_associations(
                Filters=[{'Key': 'InstanceId', 'Values': [instance_id]}]
            )

            for association in session_access_info.get('Associations', []):
                document_name = association.get('Name', '')
                if ('AWS-RunShellScript' in document_name or 
                    'AWS-RunPowerShellScript' in document_name):
                    return False

            return True
        except (ClientError, BotoCoreError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            ec2_client = connection.client('ec2')
            ssm_client = connection.client('ssm')

            reservations = self._get_instances(ec2_client)

            if not reservations:
                report.resource_ids_status['No instances found'] = False
                report.passed = False
                return report

            for reservation in reservations:
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    
                    # Check if interactive access is disabled
                    status = self._check_interactive_access(ssm_client, instance_id)
                    report.resource_ids_status[instance_id] = status
                    
                    if not status:
                        report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error checking interactive access'] = False
            report.passed = False

        return report
