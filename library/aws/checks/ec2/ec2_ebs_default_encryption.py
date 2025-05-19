"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class ec2_ebs_default_encryption(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            response = ec2_client.get_ebs_encryption_by_default()

            encryption_enabled = response.get('EbsEncryptionByDefault', False)

            if encryption_enabled:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.PASSED,
                        summary="EBS Default Encryption is enabled."
                    )
                )
            else:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="EBS Default Encryption is not enabled."
                    )
                )
        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="EBS Default Encryption"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving EBS Default Encryption status.",
                    exception=str(e)
                )
            )

        return report
