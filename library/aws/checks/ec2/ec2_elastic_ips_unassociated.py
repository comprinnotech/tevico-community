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


# Check class to identify unassociated Elastic IPs in the AWS account
class ec2_elastic_ips_unassociated(Check):

    # Main method that runs the check logic
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize a report for check
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Create EC2 client using the provided connection
            ec2 = connection.client("ec2")

            # Retrieve list of Elastic IPs (EIPs)
            response = ec2.describe_addresses()
            addresses = response.get("Addresses", [])

            # If no EIPs are found, the check is not applicable
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

            # Flag to track if any unassociated EIPs were found
            found_unassociated = False

            # Iterate through all EIPs
            for addr in addresses:
                public_ip = addr.get("PublicIp", "Unknown")           # Get EIP address
                allocation_id = addr.get("AllocationId", "Unknown")   # Get allocation ID
                associated = addr.get("InstanceId") or addr.get("NetworkInterfaceId")  # Check if EIP is associated

                if not associated:
                    # If EIP is unassociated, flag it as FAILED
                    found_unassociated = True
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=allocation_id),
                            status=CheckStatus.FAILED,
                            summary=f"EIP {public_ip} is unassociated and may incur charges."
                        )
                    )
                else:
                    # If EIP is associated, mark it as PASSED
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=allocation_id),
                            status=CheckStatus.PASSED,
                            summary=f"EIP {public_ip} is associated with a resource."
                        )
                    )

            # Final check result is FAILED if any unassociated EIPs were found
            report.status = CheckStatus.FAILED if found_unassociated else CheckStatus.PASSED

        except (BotoCoreError, ClientError) as e:
            # Handle exceptions from AWS SDK
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving Elastic IPs.",
                    exception=str(e)
                )
            )

        # Return the completed report
        return report