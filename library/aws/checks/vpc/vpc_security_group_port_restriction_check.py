"""
AUTHOR: Prajwal G
EMAIL: prajwal.govindraja@comprinno.net
DATE: 2024-05-05
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_security_group_port_restriction_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # -------------------------------------------------------------------
        # Initialize the check report.
        # -------------------------------------------------------------------
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # -------------------------------------------------------------------
            # Sets up AWS clients for EC2 and STS.
            # EC2 client: to retrieve VPCs and flow logs.
            # STS client: to retrieve account information.
            # -------------------------------------------------------------------
            ec2_client = connection.client('ec2')
            sts_client = connection.client('sts')
            
            # -------------------------------------------------------------------
            # Retrieves AWS account and region information.
            # This information is used to construct a valid ARN for each security group.
            # -------------------------------------------------------------------
            account_id = sts_client.get_caller_identity()['Account']
            region = ec2_client.meta.region_name

            # -------------------------------------------------------------------
            # Retrieves all security groups using pagination.
            # Initializes an empty list for security groups.
            # -------------------------------------------------------------------
            security_groups = []
            next_token = None
            while True:
                if next_token:
                    response = ec2_client.describe_security_groups(NextToken=next_token)
                else:
                    response = ec2_client.describe_security_groups()
                security_groups.extend(response.get("SecurityGroups", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break

            # -------------------------------------------------------------------
            # Handles case where no security groups are found.
            # If the security_groups list is empty, marks the check as NOT_APPLICABLE,
            # -------------------------------------------------------------------
            if not security_groups:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No security groups found."
                    )
                )
                return report

            # -------------------------------------------------------------------
            # These are the ports to check for unrestricted (public) access.
            # -------------------------------------------------------------------
            restricted_ports = {
                21, 22, 23, 25, 135, 139, 445, 3389, 1521, 27017,
                3306, 5432, 1433, 1434, 465, 587
            }

            # -------------------------------------------------------------------
            # Iterates over each security group to evaluate its rules.
            # For each security group:
            #   - Retrieve the complete ARN directly using the SecurityGroupArn field if available.
            #   - Otherwise, construct a valid ARN using account, region, and GroupId.
            #   - Create an AwsResource object.
            #   - Evaluate inbound and outbound rules for sensitive ports with open access.
            # -------------------------------------------------------------------
            for security_group in security_groups:
                security_group_id = security_group.get("GroupId")
                security_group_arn = security_group.get(
                    "SecurityGroupArn",
                    f"arn:aws:ec2:{region}:{account_id}:security-group/{security_group_id}"
                )
                resource = AwsResource(arn=security_group_arn)

                try:
                    # -------------------------------------------------------------------
                    # Retrieves Inbound and Outbound Rules.
                    # Get the list of inbound rules (IpPermissions) and outbound rules (IpPermissionsEgress).
                    # Combines both lists into a single list for easier processing.
                    # -------------------------------------------------------------------
                    inbound = security_group.get("IpPermissions", [])
                    outbound = security_group.get("IpPermissionsEgress", [])
                    all_rules = inbound + outbound
                    failed_ports = []

                    # -------------------------------------------------------------------
                    # Checks each rule for unrestricted access.
                    # -------------------------------------------------------------------
                    for rule in all_rules:
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        if (
                            (from_port == -1 and to_port == -1)
                            or (from_port in restricted_ports)
                            or (to_port in restricted_ports)
                        ):
                            ip_ranges = rule.get("IpRanges", [])
                            ipv6_ranges = rule.get("Ipv6Ranges", [])
                            if any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges) or \
                               any(r.get("CidrIpv6") == "::/0" for r in ipv6_ranges):
                                if from_port == -1 and to_port == -1:
                                    failed_ports.append("ALL TRAFFIC")
                                else:
                                    port = from_port if from_port in restricted_ports else to_port
                                    failed_ports.append(str(port))

                    # -------------------------------------------------------------------
                    # Records the Evaluation Result for This Security Group.
                    # If a violation is found, mark as FAILED; otherwise, mark as PASSED.
                    # Also updates the overall report status if any group fails.
                    # -------------------------------------------------------------------
                    if failed_ports:
                        report.status = CheckStatus.FAILED
                        if len(failed_ports) == 1 and failed_ports[0] == "ALL TRAFFIC":
                            summary = f"Security group {security_group_id} has open access to all traffic."
                        else:
                            summary = (
                                f"Security group {security_group_id} has open access on restricted port(s): "
                                f"{', '.join(failed_ports)}."
                            )
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=summary
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Security group {security_group_id} restricts access to sensitive ports."
                            )
                        )
                except Exception as e:
                    # -------------------------------------------------------------------
                    # Handles Exceptions for Individual Security Group Processing.
                    # If an error occurs while processing a specific security group,
                    # marks its status as UNKNOWN and record the error details.
                    # -------------------------------------------------------------------
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error processing security group {security_group_id}: {str(e)}",
                            exception=str(e)
                        )
                    )
        except Exception as e:
            # -------------------------------------------------------------------
            # Global Exception Handling.
            # If an error occurs during the retrieval of security groups,
            # marks the overall check status as UNKNOWN and log the error.
            # -------------------------------------------------------------------
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error listing security groups: {str(e)}",
                    exception=str(e)
                )
            )

        return report