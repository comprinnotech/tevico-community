"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-01
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_default_security_group_closed(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("ec2")

            vpcs = []
            next_token = None

            # Paginate through all VPCs
            while True:
                response = client.describe_vpcs(NextToken=next_token) if next_token else client.describe_vpcs()
                vpcs.extend(response.get("Vpcs", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break

            # If no VPCs exist, mark as NOT_APPLICABLE
            if not vpcs:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="VPC"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No VPCs found."
                    )
                )
                return report

            # Check each VPC's default security group
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                region = client.meta.region_name
                account_id = connection.client("sts").get_caller_identity()["Account"]

                try:
                    # Get the default security group for the VPC
                    sg_response = client.describe_security_groups(
                        Filters=[
                            {"Name": "vpc-id", "Values": [vpc_id]},
                            {"Name": "group-name", "Values": ["default"]},
                        ]
                    )
                    if not sg_response.get("SecurityGroups"):
                        continue

                    default_sg = sg_response["SecurityGroups"][0]
                    sg_id = default_sg["GroupId"]
                    sg_arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
                    resource = AwsResource(arn=sg_arn)

                    # Check if inbound and outbound rules allow traffic
                    inbound_rules = default_sg.get("IpPermissions", [])
                    outbound_rules = default_sg.get("IpPermissionsEgress", [])
                    
                    if inbound_rules and outbound_rules:
                        # Check if any rule allows traffic in both directions
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Default security group ({sg_id}) for VPC {vpc_id} allows inbound and outbound traffic."
                            )
                        )

                    elif inbound_rules:
                        # Check if any inbound rule allows traffic
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Default security group ({sg_id}) for VPC {vpc_id} allows inbound traffic."
                            )
                        )
                    
                    elif outbound_rules:
                        # Check if any outbound rule allows traffic
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Default security group ({sg_id}) for VPC {vpc_id} allows outbound traffic."
                            )
                        )
                    
                    else:
                        # No rules allow traffic
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Default security group ({sg_id}) for VPC {vpc_id} is closed."
                            )
                        )

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking default security group for VPC {vpc_id}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="VPC"),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving VPC details: {str(e)}",
                    exception=str(e)
                )
            )

        return report
