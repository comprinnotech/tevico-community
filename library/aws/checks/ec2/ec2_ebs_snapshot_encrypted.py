"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_ebs_snapshot_encrypted(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize EC2 client
        client = connection.client('ec2')

        report = CheckReport(name=__name__)

        # Initialize report status
        report.status = ResourceStatus.PASSED  # Assume passed unless we find an unencrypted snapshot
        report.resource_ids_status = {}

        try:
            # Fetch all snapshots
            res = client.describe_snapshots(OwnerIds=['self'])
            snapshots = res['Snapshots']

            for snapshot in snapshots:
                snapshot_id = snapshot['SnapshotId']
                encrypted = snapshot.get('Encrypted', False)

                # Log the encryption status of each snapshot
                report.resource_ids_status[snapshot_id] = encrypted

                if not encrypted:
                    report.status = ResourceStatus.FAILED  # If any snapshot is not encrypted, mark the report as failed

        except Exception as e:
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report