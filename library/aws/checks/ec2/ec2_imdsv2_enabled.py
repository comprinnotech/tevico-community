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


class ec2_imdsv2_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Get all running EC2 instances
            paginator = ec2_client.get_paginator('describe_instances')

            for page in paginator.paginate():
                reservations = page.get('Reservations', [])

                if not reservations:  # No running EC2 instances found
                    report.status = CheckStatus.NOT_APPLICABLE
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary="No running EC2 instances found."
                        )
                    )
                    return report  # Exit early

                for reservation in reservations:
                    for instance in reservation.get('Instances', []):
                        state = instance.get('State', {}).get('Name', '').lower()
                        if state in ["pending", "terminated"]:
                            continue  # Skip instances in pending/terminated states

                        instance_id = instance['InstanceId']

                        # Get instance metadata options with default values
                        metadata_options = instance.get('MetadataOptions', {})
                        http_tokens = metadata_options.get('HttpTokens', 'optional').lower()
                        http_endpoint = metadata_options.get('HttpEndpoint', 'disabled').lower()

                        # Check if IMDSv2 is fully enabled
                        if http_tokens == "required" and http_endpoint == "enabled":
                            status = CheckStatus.PASSED
                            summary = f"EC2 instance {instance_id} has IMDSv2 fully enabled."
                        else:
                            status = CheckStatus.FAILED
                            summary = (
                                f"EC2 instance {instance_id} does NOT fully enforce IMDSv2. "
                                f"HttpTokens: {http_tokens}, HttpEndpoint: {http_endpoint}."
                            )

                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
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
                    summary="Error retrieving EC2 metadata service configuration.",
                    exception=str(e)
                )
            )

        return report
