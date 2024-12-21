"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15

This module implements AWS Well-Architected Framework Security Pillar (SEC05-BP02) check
to verify if Network ACLs have proper restrictions for both ingress and egress traffic.
The check ensures that traffic flow is controlled in both directions (north-south traffic)
as per the principle of least privilege, excluding default rules.
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class acl_bidirectional_traffic_restriction_check(Check):
    """
    Check implementation to verify if Network ACLs enforce proper restrictions
    for both ingress and egress traffic as per AWS Well-Architected Framework.
    Default rules (rule number 32767) are ignored in this analysis.
    """
    
    # AWS default rule number for NACLs
    DEFAULT_RULE_NUMBER = 32767
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Executes the Network ACL bidirectional restriction check.
        A NACL passes if it has explicit deny rules for both ingress and egress traffic,
        excluding the default rules.

        Args:
            connection (boto3.Session): Active AWS session for making API calls

        Returns:
            CheckReport: Report containing the analysis results for each NACL
        """
        # Initialize report
        report = CheckReport(name=__name__)
        report.passed = True
        all_nacls = []

        try:
            # Initialize EC2 client and fetch Network ACLs
            client = connection.client('ec2')
            paginator = client.get_paginator('describe_network_acls')
            
            try:
                for page in paginator.paginate():
                    all_nacls.extend(page['NetworkAcls'])
            except (ClientError, BotoCoreError):
                report.passed = False
                return report

            # Analyze each NACL for proper ingress and egress restrictions
            for nacl in all_nacls:
                try:
                    nacl_id = nacl['NetworkAclId']
                    has_ingress_restriction = False
                    has_egress_restriction = False

                    # Check for explicit deny rules in both directions, ignoring default rules
                    for entry in nacl['Entries']:
                        # Skip default rules (rule number 32767)
                        if entry.get('RuleNumber') == self.DEFAULT_RULE_NUMBER:
                            continue

                        if entry['RuleAction'] == 'deny':
                            if entry['Egress']:
                                has_egress_restriction = True
                            else:
                                has_ingress_restriction = True

                        # Check if we found restrictions for both directions
                        if has_ingress_restriction and has_egress_restriction:
                            break

                    # NACL passes only if it has non-default restrictions in both directions
                    is_properly_restricted = has_ingress_restriction and has_egress_restriction
                    report.resource_ids_status[nacl_id] = is_properly_restricted

                    # If any NACL fails, the overall check fails
                    if not is_properly_restricted:
                        report.passed = False

                except (KeyError, Exception):
                    # If there's any error processing a NACL, mark it as failed
                    report.resource_ids_status[nacl_id] = False
                    report.passed = False

        except (ClientError, BotoCoreError, Exception):
            # If there's any unexpected error, mark all collected NACLs as failed
            for nacl in all_nacls:
                try:
                    nacl_id = nacl['NetworkAclId']
                    report.resource_ids_status[nacl_id] = False
                except (KeyError, Exception):
                    continue
            report.passed = False

        return report
