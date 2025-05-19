"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class acl_bidirectional_traffic_restriction_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        # Initialize EC2 client
        ec2_client = connection.client("ec2")

        try:
            # Get the account ID
            sts_client = connection.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]
            region = connection.region_name
            # Fetch all Network ACLs using pagination
            network_acls = []
            next_token = None

            while True:
                response = ec2_client.describe_network_acls(NextToken=next_token) if next_token else ec2_client.describe_network_acls()
                network_acls.extend(response.get("NetworkAcls", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no Network ACLs exist
            if not network_acls:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Network ACLs found in the account."
                    )
                )
                return report

            # Process each Network ACL
            for acl in network_acls:
                acl_id = acl["NetworkAclId"]
                acl_arn = f"arn:aws:ec2:{region}:{account_id}:network-acl/{acl_id}"

                # Exclude internal default rules (32767 - 65535)
                ingress_rules = [
                    rule for rule in acl["Entries"] if not rule["Egress"] and rule["RuleNumber"] < 32767
                ]
                egress_rules = [
                    rule for rule in acl["Entries"] if rule["Egress"] and rule["RuleNumber"] < 32767
                ]

                # Check for overly permissive rules
                has_permissive_ingress = self._has_permissive_rules(ingress_rules)
                has_permissive_egress = self._has_permissive_rules(egress_rules)

                # Determine status
                if not ingress_rules and not egress_rules:
                    summary = f"NACL {acl_id} has only default deny rules (secure configuration)."
                    status = CheckStatus.PASSED
                elif has_permissive_ingress and has_permissive_egress:
                    summary = f"NACL {acl_id} has overly permissive rules in both ingress and egress."
                    status = CheckStatus.FAILED
                elif has_permissive_ingress:
                    summary = f"NACL {acl_id} has overly permissive ingress rules."
                    status = CheckStatus.FAILED
                elif has_permissive_egress:
                    summary = f"NACL {acl_id} has overly permissive egress rules."
                    status = CheckStatus.FAILED
                else:
                    summary = f"NACL {acl_id} has no overly permissive rules."
                    status = CheckStatus.PASSED

                # Update the report
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(arn=acl_arn),
                        status=status,
                        summary=summary
                    )
                )

                # Mark report as failed if any NACL is non-compliant
                if status == CheckStatus.FAILED:
                    report.status = CheckStatus.FAILED

        except ClientError as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error fetching Network ACLs: {str(e)}",
                    exception=str(e)
                )
            )
        # print(report)
        return report

    def _has_permissive_rules(self, rules):
        """
        Check if there are any permissive ALLOW rules with 0.0.0.0/0
        """
        for rule in rules:
            is_open_cidr = rule.get("CidrBlock") == "0.0.0.0/0"
            is_allow_rule = rule.get("RuleAction") == "allow"

            if is_open_cidr and is_allow_rule:
                return True
        return False
