"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ensure_aws_support_role(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless the support role or policy is missing
        report.passed = True
        report.resource_ids_status = {}

        # Define the required policy name and expected role name
        required_policy_name = "AWSSupportAccess"
        support_role_created = False

        try:
            # Step 1: Check if the AWSSupportAccess policy exists
            policy_arn = None
            policies = client.list_policies(Scope='AWS', OnlyAttached=False)['Policies']
            for policy in policies:
                if policy['PolicyName'] == required_policy_name:
                    policy_arn = policy['Arn']
                    break

            if not policy_arn:
                # If the AWSSupportAccess policy does not exist, fail the check
                report.passed = False
                report.resource_ids_status[f"Policy {required_policy_name} does not exist in the account"] = False
                return report

            # Step 2: Check if the policy is attached to any roles
            paginator = client.get_paginator('list_entities_for_policy')
            attached_roles = []
            for page in paginator.paginate(PolicyArn=policy_arn, EntityFilter='Role'):
                attached_roles.extend(page['PolicyRoles'])

            if attached_roles:
                # If roles are attached to the policy, check for specific role names
                role_names = [role['RoleName'] for role in attached_roles]
                support_role_created = True
                report.resource_ids_status[f"Policy {required_policy_name} is attached to roles: {', '.join(role_names)}"] = True
            else:
                # If no roles are attached, fail the check
                report.passed = False
                report.resource_ids_status[f"Policy {required_policy_name} is not attached to any roles"] = False

            # Step 3: Ensure a support-specific role is present (optional validation)
            if support_role_created and not any("Support" in role for role in role_names):
                report.passed = False
                report.resource_ids_status["No support-specific role found attached to the policy"] = False

        except Exception as e:
            # Handle unexpected errors
            logging.error(f"Error while checking AWS support role: {e}")
            report.passed = False
            report.resource_ids_status["Error occurred while checking support role"] = False

        return report
