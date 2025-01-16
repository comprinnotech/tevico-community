"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_network_acl_bidirectional_traffic_restriction_check(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Initialize EC2 client
        ec2_client = connection.client('ec2')

        try:
            # Initialize pagination for Network ACLs
            network_acls = []
            next_token = None

            while True:
                if next_token:
                    response = ec2_client.describe_network_acls(NextToken=next_token)
                else:
                    response = ec2_client.describe_network_acls()

                network_acls.extend(response.get('NetworkAcls', []))
                next_token = response.get('NextToken', None)

                if not next_token:
                    break

            # Check if there are no Network ACLs
            if not network_acls:
                report.status = ResourceStatus.NOT_APPLICABLE
                return report

            # Process each Network ACL
            for acl in network_acls:
                acl_id = acl['NetworkAclId']

                # Filter out the default deny rules (rule number 32767)
                ingress_rules = [
                    rule for rule in acl['Entries'] if not rule['Egress'] and rule['RuleNumber'] != 32767
                ]
                egress_rules = [
                    rule for rule in acl['Entries'] if rule['Egress'] and rule['RuleNumber'] != 32767
                ]

                # Check for overly permissive rules in both directions
                has_permissive_ingress = self._has_permissive_rules(ingress_rules)
                has_permissive_egress = self._has_permissive_rules(egress_rules)

                # Prepare the status message
                if not ingress_rules and not egress_rules:
                    status_message = f"NACL {acl_id} has only default deny rules (secure configuration)"
                    report.resource_ids_status[status_message] = True
                elif has_permissive_ingress and has_permissive_egress:
                    status_message = f"NACL {acl_id} has permissive rules in both ingress and egress"
                    report.resource_ids_status[status_message] = False
                    report.status = ResourceStatus.FAILED
                elif has_permissive_ingress:
                    status_message = f"NACL {acl_id} has permissive rules in ingress"
                    report.resource_ids_status[status_message] = False
                    report.status = ResourceStatus.FAILED
                elif has_permissive_egress:
                    status_message = f"NACL {acl_id} has permissive rules in egress"
                    report.resource_ids_status[status_message] = False
                    report.status = ResourceStatus.FAILED
                else:
                    status_message = f"NACL {acl_id} has no permissive rules"
                    report.resource_ids_status[status_message] = True

        except Exception as e:
            # Handle API errors
            report.resource_ids_status["NACL listing error"] = False
            report.status = ResourceStatus.UNKNOWN

        return report

    def _has_permissive_rules(self, rules):
        """
        Check if there are any permissive ALLOW rules with 0.0.0.0/0
        """
        for rule in rules:
            # Check if the rule allows traffic from anywhere
            is_open_cidr = rule.get('CidrBlock') == '0.0.0.0/0'
            is_allow_rule = rule.get('RuleAction') == 'allow'

            if is_open_cidr and is_allow_rule:
                return True

        return False
