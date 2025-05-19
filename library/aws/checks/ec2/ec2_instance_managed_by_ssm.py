"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class ec2_instance_managed_by_ssm(Check):
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
                            summary="No running EC2 instances found.",
                        )
                    )
                    return report  # Exit early if no instances exist

                instance_ids = [
                    instance["InstanceId"]
                    for reservation in reservations
                    for instance in reservation.get("Instances", [])
                    if instance.get("State", {}).get("Name", "").lower() not in ["pending", "terminated"]
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

                # Get SSM managed instances
                ssm_response = ssm_client.describe_instance_information(
                    Filters=[{"Key": "InstanceIds", "Values": instance_ids}]
                )
                ssm_managed_instances = {inst["InstanceId"] for inst in ssm_response.get("InstanceInformationList", [])}

                for instance_id in instance_ids:
                    if instance_id in ssm_managed_instances:
                        status = CheckStatus.PASSED
                        summary = f"EC2 instance {instance_id} is managed by SSM."
                    else:
                        status = CheckStatus.FAILED
                        summary = f"EC2 instance {instance_id} is NOT managed by SSM."

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=instance_id),
                            status=status,
                            summary=summary,
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving EC2 SSM management status.",
                    exception=str(e),
                )
            )

        return report
