"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2024-11-12
"""
import boto3
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_ec2instance_automatic_protection_check(Check):
    """
    Check to ensure EC2 instances managed by SSM have termination protection enabled.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the check to verify if EC2 instances managed by SSM have termination protection enabled.
        """
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        
        try:
            ec2_client = connection.client('ec2')
            ssm_client = connection.client('ssm')
            
            # Get all instances using pagination
            instance_ids = []
            paginator = ec2_client.get_paginator("describe_instances")
            
            for page in paginator.paginate():
                reservations = page.get("Reservations", [])
                if not reservations:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary="No EC2 instances found.",
                        )
                    )
                    return report
                
                
            # Case 2: Check if any running instances exist
                instance_ids = [
                    instance["InstanceId"]
                    for reservation in reservations
                    for instance in reservation.get("Instances", [])
                    if instance.get("State", {}).get("Name", "").lower() in ["running"]
                ]

                if not instance_ids:
                    report.status = CheckStatus.NOT_APPLICABLE
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary="No running EC2 instances found.",
                        )
                    )
                    return report
            
            # Get all SSM managed instances in one call
            ssm_managed_instances = set()
            try:
                ssm_paginator = ssm_client.get_paginator('describe_instance_information')
                for page in ssm_paginator.paginate():
                    for instance in page.get('InstanceInformationList', []):
                        ssm_managed_instances.add(instance['InstanceId'])
            except ClientError as e:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="SSM"),
                        status=CheckStatus.UNKNOWN,
                        summary=f"Error retrieving SSM instance information: {str(e)}",
                        exception=str(e)
                    )
                )
                report.status = CheckStatus.UNKNOWN
                return report
            
            # Check if any instances are managed by SSM
            if not ssm_managed_instances:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EC2 instances are managed by SSM."
                    )
                )
                return report
            
            # Check if any instances are both running and managed by SSM
            ssm_managed_running_instances = [id for id in instance_ids if id in ssm_managed_instances]
            if not ssm_managed_running_instances:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No running EC2 instances are managed by SSM."
                    )
                )
                return report
            
            # Check termination protection for each SSM-managed instance
            for instance_id in instance_ids:
                if instance_id not in ssm_managed_instances:
                    # Skip instances not managed by SSM
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary=f"EC2 instance {instance_id} is not managed by SSM."
                        )
                    )
                    continue
                
                try:
                    # Check termination protection
                    protection_info = ec2_client.describe_instance_attribute(
                        InstanceId=instance_id,
                        Attribute='disableApiTermination'
                    )
                    is_protected = protection_info.get('DisableApiTermination', {}).get('Value', False)
                    
                    if is_protected:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
                                status=CheckStatus.PASSED,
                                summary=f"EC2 instance {instance_id} has termination protection enabled."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
                                status=CheckStatus.FAILED,
                                summary=f"EC2 instance {instance_id} does not have termination protection enabled."
                            )
                        )
                        report.status = CheckStatus.FAILED
                
                except ClientError as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking termination protection for instance {instance_id}: {str(e)}",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN
            
        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="EC2"),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Unexpected error during check execution: {str(e)}",
                    exception=str(e)
                )
            )
            report.status = CheckStatus.UNKNOWN
            
        return report
