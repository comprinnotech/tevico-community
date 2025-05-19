"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12
"""

import re
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class kms_cmk_are_used(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED  # Default to FAILED unless we find a valid CMK
        report.resource_ids_status = []

        try:
            client = connection.client('kms')
            paginator = client.get_paginator('list_keys')

            customer_managed_keys_found = False

            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key['KeyId']
                    # Retrieve key details
                    key_info = client.describe_key(KeyId=key_id)
                    key_metadata = key_info.get('KeyMetadata', {})

                    try:
                        key_manager = key_metadata.get('KeyManager')
                        key_state = key_metadata.get('KeyState')

                        # Process only customer-managed keys
                        if key_manager != 'CUSTOMER':
                            continue

                        # Check if the key is enabled
                        is_enabled = key_state == 'Enabled'

                        resource_status = ResourceStatus(
                            resource=AwsResource(arn=key_metadata.get('Arn')),
                            status=CheckStatus.PASSED if is_enabled else CheckStatus.FAILED,
                            summary=f"Customer-managed CMK {key_id} is {'enabled' if is_enabled else 'disabled'}."
                        )

                        report.resource_ids_status.append(resource_status)

                        if is_enabled:
                            customer_managed_keys_found = True

                    except ClientError as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=key_metadata.get('Arn')),
                                status=CheckStatus.FAILED,
                                summary=f"Failed to describe CMK {key_id}: {str(e)}"
                            )
                        )

            # Set overall check status based on whether any enabled CMKs were found
            if customer_managed_keys_found:
                report.status = CheckStatus.PASSED

        except Exception as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error fetching KMS keys: {str(e)}"
                )
            )
        return report
