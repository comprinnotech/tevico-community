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


class ec2_ebs_volume_encryption(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Get all EBS volumes
            paginator = ec2_client.get_paginator('describe_volumes')
            volumes = []

            for page in paginator.paginate():
                volumes.extend(page.get('Volumes', []))

            if not volumes:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EBS volumes found."
                    )
                )
                return report

            for volume in volumes:
                volume_id = volume['VolumeId']
                encrypted = volume.get('Encrypted', False)

                status = CheckStatus.PASSED if encrypted else CheckStatus.FAILED
                summary = (
                    f"EBS volume {volume_id} is encrypted."
                    if encrypted
                    else f"EBS volume {volume_id} is NOT encrypted."
                )

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=volume_id),
                        status=status,
                        summary=summary
                    )
                )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving EBS volume encryption status.",
                    exception=str(e)
                )
            )

        return report
