"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-1-16
"""
import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_attached_policy_admin_privileges_found(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless admin privileges are found
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Define the policy name that grants admin privileges
        admin_policy_name = "AdministratorAccess"

        try:
            # Step 1: Check users with the admin policy attached
            users = client.list_users()['Users']
            for user in users:
                attached_policies = client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                if any(policy['PolicyName'] == admin_policy_name for policy in attached_policies):
                    # Mark user as non-compliant
                    report.resource_ids_status[f"User {user['UserName']} has admin privileges"] = False
                    report.status = ResourceStatus.FAILED

            # Step 2: Check roles with the admin policy attached
            roles = client.list_roles()['Roles']
            for role in roles:
                attached_policies = client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                if any(policy['PolicyName'] == admin_policy_name for policy in attached_policies):
                    # Mark role as non-compliant
                    report.resource_ids_status[f"Role {role['RoleName']} has admin privileges"] = False
                    report.status = ResourceStatus.FAILED

            # If no admin privileges are found, mark as compliant
            if report.status == ResourceStatus.PASSED:
                report.resource_ids_status["No users or roles with admin privileges"] = True

        except Exception as e:
            # Handle unexpected errors
            logging.error(f"Error while checking for admin privileges: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["Error occurred while checking for admin privileges"] = False

        return report
