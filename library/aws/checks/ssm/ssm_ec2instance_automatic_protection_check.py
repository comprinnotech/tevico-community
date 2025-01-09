"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ssm_ec2instance_automatic_protection_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            ec2_client = connection.client('ec2')
            ssm_client = connection.client('ssm')

            # Get all instances managed by SSM
            ssm_instances = ssm_client.describe_instance_information()
            
            if not ssm_instances.get('InstanceInformationList'):
                report.resource_ids_status['No SSM managed instances found'] = False
                report.passed = False
                return report

            # Check termination protection for each SSM managed instance
            for instance in ssm_instances['InstanceInformationList']:
                instance_id = instance['InstanceId']
                
                try:
                    protection_info = ec2_client.describe_instance_attribute(
                        InstanceId=instance_id,
                        Attribute='disableApiTermination'
                    )
                    
                    is_protected = protection_info['DisableApiTermination']['Value']
                    report.resource_ids_status[instance_id] = is_protected

                except (ClientError, BotoCoreError, Exception):
                    report.resource_ids_status[instance_id] = False

            # Check passes only if all SSM managed instances have termination protection
            report.passed = all(report.resource_ids_status.values())

        except (ClientError, BotoCoreError, Exception):
            report.resource_ids_status['Error checking instance protection'] = False
            report.passed = False

        return report
