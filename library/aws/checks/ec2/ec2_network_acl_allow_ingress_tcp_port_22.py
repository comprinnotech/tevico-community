"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-14
"""

from os import name
import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_network_acl_allow_ingress_tcp_port_22(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("ec2")

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Get the account ID
            sts_client = connection.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]

            # Get the AWS region
            region = connection.region_name

            # Pagination to get all network ACLs
            acls = []
            next_token = None

            while True:
                response = client.describe_network_acls(NextToken=next_token) if next_token else client.describe_network_acls()
                acls.extend(response.get("NetworkAcls", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no ACLs exist
            if not acls:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Network ACLs found in the account."
                    )
                )
                return report

            # Define the TCP protocol and port to check
            tcp_protocol = "6"
            check_port = 22

            # Check each network ACL for rules allowing ingress on port 22
            for acl in acls:
                acl_id = acl["NetworkAclId"]
                acl_arn = f"arn:aws:ec2:{region}:{account_id}:network-acl/{acl_id}"
                acl_allows_ingress = False

                for entry in acl["Entries"]:
                    if entry["Egress"]:  # Skip egress rules
                        continue

                    if entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("RuleAction") == "allow":
                        if entry.get("Protocol") in [tcp_protocol, "-1"]:  # Check TCP protocol or all protocols
                            port_range = entry.get("PortRange")
                            if not port_range or (port_range["From"] <= check_port <= port_range["To"]):
                                acl_allows_ingress = True
                                break

                # Record the result for this ACL
                if acl_allows_ingress:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=acl_arn),
                            status=CheckStatus.FAILED,
                            summary=f"NACL {acl_id} allows ingress on port 22 from 0.0.0.0/0."
                        )
                    )
                    report.status = CheckStatus.FAILED
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=acl_arn),
                            status=CheckStatus.PASSED,
                            summary=f"NACL {acl_id} does not allow ingress on port 22 from 0.0.0.0/0."
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching Network ACLs: {str(e)}",
                    exception=str(e)
                )
            )
        return report
