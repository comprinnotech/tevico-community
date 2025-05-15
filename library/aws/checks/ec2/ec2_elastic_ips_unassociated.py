"""
AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 2025-05-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class ec2_elastic_ips_unassociated(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            ec2 = connection.client("ec2")
            response = ec2.describe_addresses()
            addresses = response.get("Addresses", [])

            if not addresses:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Elastic IPs allocated in this account."
                    )
                )
                return report

            found_unassociated = False

            for addr in addresses:
                public_ip = addr.get("PublicIp", "Unknown")
                allocation_id = addr.get("AllocationId", "Unknown")
                associated = addr.get("InstanceId") or addr.get("NetworkInterfaceId")

                if not associated:
                    found_unassociated = True
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=allocation_id),
                            status=CheckStatus.FAILED,
                            summary=f"EIP {public_ip} is unassociated and may incur charges."
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=allocation_id),
                            status=CheckStatus.PASSED,
                            summary=f"EIP {public_ip} is associated with a resource."
                        )
                    )

            report.status = CheckStatus.FAILED if found_unassociated else CheckStatus.PASSED

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving Elastic IPs.",
                    exception=str(e)
                )
            )

        return report