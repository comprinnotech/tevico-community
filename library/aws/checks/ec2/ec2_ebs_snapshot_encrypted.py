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


class ec2_ebs_snapshot_encrypted(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Get all EBS snapshots owned by the account
            paginator = ec2_client.get_paginator('describe_snapshots')
            snapshots = []

            for page in paginator.paginate(OwnerIds=['self']):  # Fetch only self-owned snapshots
                snapshots.extend(page.get('Snapshots', []))

            if not snapshots:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EBS snapshots found."
                    )
                )
                return report

            for snapshot in snapshots:
                snapshot_id = snapshot['SnapshotId']
                encrypted = snapshot.get('Encrypted', False)

                status = CheckStatus.PASSED if encrypted else CheckStatus.FAILED
                summary = (
                    f"EBS snapshot {snapshot_id} is encrypted."
                    if encrypted
                    else f"EBS snapshot {snapshot_id} is NOT encrypted."
                )

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=snapshot_id),
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
                    summary="Error retrieving EBS snapshot encryption status.",
                    exception=str(e)
                )
            )

        return report
