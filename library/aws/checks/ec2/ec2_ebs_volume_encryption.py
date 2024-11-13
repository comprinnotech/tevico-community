"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check


class ec2_ebs_volume_encryption(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize EC2 client
        client = connection.client('ec2')

        # Fetch all volumes
        res = client.describe_volumes()
        volumes = res['Volumes']
        
        report = CheckReport(name=__name__)
        report.passed = True  # Assume passed unless we find an unencrypted volume
        report.resource_ids_status = {}

        for volume in volumes:
            volume_id = volume['VolumeId']
            encrypted = volume.get('Encrypted', False)

            # Log the encryption status of each volume
            report.resource_ids_status[volume_id] = encrypted

            if not encrypted:
                report.passed = False  # If any volume is not encrypted, mark the report as failed

        return report                                       