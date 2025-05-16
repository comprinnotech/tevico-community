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
    """Check to identify unassociated Elastic IPs in an AWS account."""

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Executes the check to find unassociated Elastic IPs.

        Args:
            connection (boto3.Session): The boto3 session used to create the EC2 client.

        Returns:
            CheckReport: The report containing the results of the EIP association check.
        """
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Create EC2 client from the given session
            ec2 = connection.client("ec2")

            # Retrieve all allocated Elastic IPs
            response = ec2.describe_addresses()
            addresses = response.get("Addresses", [])

            # If there are no EIPs, mark the check as not applicable
            if not addresses:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource = GeneralResource(name=""),
                        status = CheckStatus.NOT_APPLICABLE,
                        summary = "No Elastic IPs allocated in this account."
                    )
                )
                return report

            # Track if any unassociated EIPs are found
            found_unassociated = False

            # Analyze each EIP to determine if it is associated
            for addr in addresses:
                public_ip = addr.get("PublicIp", "Unknown")
                allocation_id = addr.get("AllocationId", "Unknown")
                associated = addr.get("InstanceId") or addr.get("NetworkInterfaceId")

                if not associated:
                    # EIP is not associated with any resource
                    found_unassociated = True
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource = GeneralResource(name=allocation_id),
                            status = CheckStatus.FAILED,
                            summary = f"EIP {public_ip} is unassociated and may incur charges."
                        )
                    )
                else:
                    # EIP is associated with a resource (instance or network interface)
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource = GeneralResource(name=allocation_id),
                            status = CheckStatus.PASSED,
                            summary = f"EIP {public_ip} is associated with a resource."
                        )
                    )

            # Determine overall check status based on individual results
            report.status = CheckStatus.FAILED if found_unassociated else CheckStatus.PASSED

        except (BotoCoreError, ClientError) as e:
            # AWS API call failed, mark the status as UNKNOWN and include the exception
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource = GeneralResource(name=""),
                    status = CheckStatus.UNKNOWN,
                    summary = "Error retrieving Elastic IPs.",
                    exception = str(e)
                )
            )

        return report