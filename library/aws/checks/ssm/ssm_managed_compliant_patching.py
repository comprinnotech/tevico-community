"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-09
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_managed_compliant_patching(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client("ec2")
        ssm_client = connection.client("ssm")
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            paginator = ec2_client.get_paginator("describe_instances")
            instance_data = []

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
                        summary="No running EC2 instances found."
                    )
                )
                return report

            # Describe all managed instances (without filters, AWS limitation workaround)
            ssm_managed_instances = set()
            
            try:
                ssm_paginator = ssm_client.get_paginator("describe_instance_information")
                for ssm_page in ssm_paginator.paginate():
                    for info in ssm_page.get("InstanceInformationList", []):
                        ssm_managed_instances.add(info["InstanceId"])
            except ClientError as e:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.UNKNOWN,
                        summary=f"Error retrieving SSM managed instances: {str(e)}",
                        exception=str(e)
                    )
                )
                return report

            # Batch process for compliance check
            batch_size = 50
            for i in range(0, len(instance_data), batch_size):
                batch = instance_data[i:i + batch_size]

                for instance in batch:
                    instance_id = instance["id"]
                    instance_name = instance["name"]

                    if instance_id not in ssm_managed_instances:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"EC2 instance {instance_id} ({instance_name}) is not managed by SSM."
                            )
                        )
                        continue

                    try:
                        response = ssm_client.list_resource_compliance_summaries(
                            Filters=[
                                {"Key": "ComplianceType", "Values": ["Patch"]},
                                {"Key": "InstanceId", "Values": [instance_id]}
                            ]
                        )

                        summaries = response.get("ResourceComplianceSummaryItems", [])
                        if not summaries:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=instance_id),
                                    status=CheckStatus.FAILED,
                                    summary=f"EC2 instance {instance_id} ({instance_name}) has no patch compliance summary available."
                                )
                            )
                        else:
                            status = summaries[0].get("Status")
                            if status == "COMPLIANT":
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=instance_id),
                                        status=CheckStatus.PASSED,
                                        summary=f"EC2 instance {instance_id} ({instance_name}) is patch compliant."
                                    )
                                )
                            else:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=instance_id),
                                        status=CheckStatus.FAILED,
                                        summary=f"EC2 instance {instance_id} ({instance_name}) is NOT patch compliant."
                                    )
                                )

                    except ClientError as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Error retrieving patch compliance for {instance_id} ({instance_name}): {str(e)}",
                                exception=str(e)
                            )
                        )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving EC2 instance information: {str(e)}",
                    exception=str(e)
                )
            )
        return report
