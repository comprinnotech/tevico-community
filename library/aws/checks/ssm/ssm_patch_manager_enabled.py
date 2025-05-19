"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-09
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_patch_manager_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client("ec2")
        ssm_client = connection.client("ssm")
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            paginator = ec2_client.get_paginator("describe_instances")

            for page in paginator.paginate():
                reservations = page.get("Reservations", [])
                if not reservations:
                    report.status = CheckStatus.NOT_APPLICABLE
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary="No EC2 instances found.",
                        )
                    )
                    return report  # Exit early if no instances exist

                # Get all running instances
                instance_data = []
                for reservation in reservations:
                    for instance in reservation.get("Instances", []):
                        state = instance.get("State", {}).get("Name", "").lower()
                        if state == "running":
                            instance_id = instance["InstanceId"]
                            instance_name = next(
                                (tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"),
                                "Unnamed"
                            )
                            instance_data.append({"id": instance_id, "name": instance_name})

                if not instance_data:
                    report.status = CheckStatus.NOT_APPLICABLE
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary="No running EC2 instances found.",
                        )
                    )
                    return report

                # Get all instance IDs for SSM API calls
                instance_ids = [instance["id"] for instance in instance_data]

                # Get SSM managed instances
                try:
                    ssm_response = ssm_client.describe_instance_information(
                        Filters=[{"Key": "InstanceIds", "Values": instance_ids}]
                    )
                    ssm_managed_instances = {inst["InstanceId"] for inst in ssm_response.get("InstanceInformationList", [])}
                except ClientError as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving SSM managed instances: {str(e)}",
                            exception=str(e)
                        )
                    )

                # Process instances in batches for patch state check
                batch_size = 50  # AWS API limit
                for i in range(0, len(instance_data), batch_size):
                    batch = instance_data[i:i+batch_size]
                    
                    # Filter to only check SSM managed instances
                    managed_batch = [instance for instance in batch if instance["id"] in ssm_managed_instances]
                    managed_batch_ids = [instance["id"] for instance in managed_batch]
                    
                    # Process unmanaged instances in this batch
                    for instance in batch:
                        if instance["id"] not in ssm_managed_instances:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=instance["id"]),
                                    status=CheckStatus.FAILED,
                                    summary=f"EC2 instance {instance['id']} ({instance['name']}) is not managed by SSM.",
                                )
                            )
                    
                    # Skip API call if no managed instances in this batch
                    if not managed_batch_ids:
                        continue
                        
                    # Check patch states for managed instances
                    try:
                        patch_states = ssm_client.describe_instance_patch_states(
                            InstanceIds=managed_batch_ids
                        )
                        
                        # Create a map of instance IDs to patch states for quick lookup
                        patch_state_map = {
                            state["InstanceId"]: state 
                            for state in patch_states.get("InstancePatchStates", [])
                        }
                        
                        # Process managed instances in this batch
                        for instance in managed_batch:
                            instance_id = instance["id"]
                            instance_name = instance["name"]
                            
                            if instance_id in patch_state_map:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=instance_id),
                                        status=CheckStatus.PASSED,
                                        summary=f"EC2 instance {instance_id} ({instance_name}) has Patch Manager enabled.",
                                    )
                                )
                            else:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=instance_id),
                                        status=CheckStatus.FAILED,
                                        summary=f"EC2 instance {instance_id} ({instance_name}) is managed by SSM but Patch Manager is not enabled.",
                                    )
                                )
                                
                    except ClientError as e:
                        # Handle errors for this batch
                        for instance in managed_batch:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=instance["id"]),
                                    status=CheckStatus.UNKNOWN,
                                    summary=f"Error checking patch state for instance {instance['id']} ({instance['name']}): {str(e)}",
                                    exception=str(e)
                                )
                            )

        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving EC2 instances: {str(e)}",
                    exception=str(e)
                )
            )

        return report
