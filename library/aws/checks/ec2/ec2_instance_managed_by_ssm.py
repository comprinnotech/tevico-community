"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, ResourceStatus, AwsResource, GeneralResource
from tevico.engine.entities.check.check import Check


class ec2_instance_managed_by_ssm(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize clients for EC2 and SSM
        ec2_client = connection.client('ec2')
        ssm_client = connection.client('ssm')

        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Assume passed unless we find an unmanaged instance
        report.resource_ids_status = []

        # Fetch all EC2 instances
        try:
            instances_response = ec2_client.describe_instances()
            instances = [i for r in instances_response['Reservations'] for i in r['Instances']]
        except Exception as e:
            report.status = CheckStatus.FAILED
            return report

        # Remove instances in states ["pending", "terminated", "stopped"]
        instances = [
            instance for instance in instances 
            if instance['State']['Name'] not in ["pending", "terminated", "stopped"]
        ]

        # Check if there are instances
        if not instances:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No instances available."
                    )
            )
            return report

        for instance in instances:
            instance_id = instance['InstanceId']
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=instance_id),
                    status=CheckStatus.PASSED,
                    summary=''
                )
            )

            # Check if the instance is managed by SSM
            try:
                managed_instances_response = ssm_client.describe_instance_information()
                managed_instances = managed_instances_response['InstanceInformationList']
                managed_instance_ids = {m['InstanceId'] for m in managed_instances}

                if instance_id not in managed_instance_ids:
                    report.status = CheckStatus.FAILED
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.FAILED,
                            summary=f"EC2 instance {instance_id} is not managed by SSM."
                        )
                    )
            except Exception as e:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary=f"Error in getting instance details."
                    )
                )

        return report
