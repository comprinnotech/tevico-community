"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, ConnectionError, EndpointConnectionError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_ec2instance_remove_interactive_access_check(Check):
    """
    Check to ensure EC2 instances managed by SSM have interactive access removed.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the check to verify if EC2 instances have interactive access removed.
        """
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
        
        try:
            ec2_client = connection.client('ec2')
            ssm_client = connection.client('ssm')
            
            # Get all running EC2 instances
            all_running_instances = []
            instance_details = {}
            
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
                
                for reservation in reservations:
                    for instance in reservation.get("Instances", []):
                        if instance.get("State", {}).get("Name", "").lower() == "running":
                            instance_id = instance["InstanceId"]
                            all_running_instances.append(instance_id)
                            instance_details[instance_id] = instance
            
            # Case 1: No instances found
            if not all_running_instances:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No running EC2 instances found.",
                    )
                )
                return report
            
            # Case 3: Process running instances
            
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
                        resource=GeneralResource(name=""),
                        status=CheckStatus.UNKNOWN,
                        summary="Error accessing SSM instance information.",
                        exception=str(e)
                    )
                )
                return report
                
            # Process each instance
            for instance_id in all_running_instances:
                
                # Check if instance is managed by SSM
                if instance_id not in ssm_managed_instances:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary=f"EC2 instance {instance_id} is not managed by SSM."
                        )
                    )
                    continue
                
                # Check for interactive access methods
                access_methods = []
                
                # Get instance details from our cached dictionary
                instance = instance_details.get(instance_id, {})
                
                # Check SSH access directly (no caching)
                if self._has_ssh_access(instance, ec2_client):
                    access_methods.append("SSH (port 22)")
                
                # Check for interactive shell access via SSM document associations
                if self._has_ssm_shell_access(instance_id, ssm_client):
                    access_methods.append("SSM shell scripts")
                
                # Any SSM-managed instance has Session Manager access by default
                access_methods.append("Session Manager")
                
                # Report findings
                if access_methods:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=CheckStatus.FAILED,
                            summary=f"EC2 instance {instance_id} has interactive access enabled via: {', '.join(access_methods)}."
                        )
                    )
                    report.status = CheckStatus.FAILED
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=CheckStatus.PASSED,
                            summary=f"EC2 instance {instance_id} does not have interactive access enabled."
                        )
                    )
                    
        except ClientError as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="AWS API error during interactive access check execution.",
                    exception=str(e)
                )
            )
        except ConnectionError as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Network connection error during check execution.",
                    exception=str(e)
                )
            )
        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Unexpected error during interactive access check execution.",
                    exception=str(e)
                )
            )
            
        return report
    
    def _has_ssh_access(self, instance, ec2_client):
        """
        Check if an instance has SSH access via security groups.
        """
        for sg in instance.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            
            # Get security group details directly (no caching)
            sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])
            
            for sg_detail in sg_details.get('SecurityGroups', []):
                for rule in sg_detail.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 0)
                    if (from_port <= 22 <= to_port) and rule.get('IpRanges'):
                        return True
        return False
    
    def _has_ssm_shell_access(self, instance_id, ssm_client):
        """Check if an instance has interactive shell access via SSM document associations."""
        try:
            session_access_info = ssm_client.list_associations(
                AssociationFilterList=[{'key': 'InstanceId', 'value': instance_id}]
            )
            
            for association in session_access_info.get('Associations', []):
                document_name = association.get('Name', '')
                if 'AWS-RunShellScript' in document_name or 'AWS-RunPowerShellScript' in document_name:
                    return True
            return False
        except ClientError:
            # If we can't check associations, assume no shell access
            return False
