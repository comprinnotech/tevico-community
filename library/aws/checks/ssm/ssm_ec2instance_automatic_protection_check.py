"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_ec2instance_automatic_protection_check(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ec2_client = connection.client('ec2')
        ssm_client = connection.client('ssm')

        instances = ec2_client.describe_instances()['Reservations']

        for reservation in instances:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                
                try:
                    ssm_instance_info = ssm_client.describe_instance_information(Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}])

                    if ssm_instance_info['InstanceInformationList']:
                        protection_info = ec2_client.describe_instance_attribute(
                            InstanceId=instance_id,
                            Attribute='disableApiTermination'
                        )
                        is_protected = protection_info['DisableApiTermination']['Value']

                        if is_protected:
                            report.resource_ids_status[instance_id] = True  
                        else:
                            report.resource_ids_status[instance_id] = False  
                            report.status = ResourceStatus.FAILED

                    else:
                        report.resource_ids_status[instance_id] = False  
                        report.status = ResourceStatus.FAILED

                except (ssm_client.exceptions.InvalidInstanceId, ec2_client.exceptions.ClientError) as e:
                    report.resource_ids_status[instance_id] = False  
                    report.status = ResourceStatus.FAILED

        if all(report.resource_ids_status.values()):
            report.status = ResourceStatus.PASSED

        return report
