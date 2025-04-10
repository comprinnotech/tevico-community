"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_ec2instance_remove_interactive_access_check(Check):

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
                       
                        instance_role = instance.get('IamInstanceProfile', {}).get('Arn', '')

                        
                        session_access_info = ssm_client.list_associations(
                            AssociationFilterList=[{'key': 'InstanceId', 'value': instance_id}]
                        )
                        interactive_access_enabled = False

                        for association in session_access_info['Associations']:
                            document_name = association['Name']
                            if 'AWS-RunShellScript' in document_name or 'AWS-RunPowerShellScript' in document_name:
                                interactive_access_enabled = True

                        if interactive_access_enabled:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=instance_id),
                                    status=CheckStatus.FAILED,
                                    summary=''
                                )
                            )
                            report.status = CheckStatus.FAILED
                        else:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=instance_id),
                                    status=CheckStatus.PASSED,
                                    summary=''
                                )
                            )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
                                status=CheckStatus.FAILED,
                                summary=''
                            )
                        )
                        report.status = CheckStatus.FAILED

                except (ssm_client.exceptions.InvalidInstanceId, ec2_client.exceptions.ClientError) as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=CheckStatus.FAILED,
                            summary=''
                        )
                    )
                    report.status = CheckStatus.FAILED

        if all(report.resource_ids_status):
            report.status = CheckStatus.PASSED

        return report
