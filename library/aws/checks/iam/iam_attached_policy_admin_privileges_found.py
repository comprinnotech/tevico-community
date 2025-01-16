"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_attached_policy_admin_privileges_found(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        # Initialize the IAM client
        iam_client = connection.client('iam')
        # print("[INFO] Initialized IAM client.")

        # Fetch all users and their attached policies
        users = iam_client.list_users()['Users']
        # print(f"[INFO] Retrieved {len(users)} IAM users.")
        
        findings = []

        for user in users:
            user_name = user['UserName']
            # print(f"[INFO] Processing IAM user: {user_name}")
            
            policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            # print(f"[INFO] {user_name} has {len(policies)} attached policies.")

            for policy in policies:
                policy_arn = policy['PolicyArn']
                policy_details = iam_client.get_policy(PolicyArn=policy_arn)
                policy_name = policy_details['Policy']['PolicyName']
                # print(f"[INFO] Fetching details for policy: {policy_name} (ARN: {policy_arn})")

                # Check if the policy is an AWS-managed policy
                if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                    # print(f"[INFO] Policy {policy_name} is an AWS-managed policy.")
                    
                    # Specifically check for AdministratorAccess policy
                    if policy_name == 'AdministratorAccess':
                        # print(f"[WARNING] User {user_name} has AdministratorAccess policy attached, which grants full admin privileges.")
                        findings.append(f"User {user_name} has attached AWS-managed AdministratorAccess policy with full administrative privileges.")
                        break  # No need to check further policies for this user
                        
                    # Check for full administrative privileges (*:*)
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_details['Policy']['DefaultVersionId']
                    )
                    policy_document = policy_version['PolicyVersion']['Document']

                    if 'Statement' in policy_document:
                        for statement in policy_document['Statement']:
                            if statement.get('Effect') == 'Allow' and '*:*' in statement.get('Action', []):
                                # print(f"[WARNING] Policy {policy_name} grants full administrative privileges (*:*) to user {user_name}.")
                                findings.append(f"User {user_name} has attached AWS-managed policy {policy_name} with full administrative privileges.")
                                break  # Stop after detecting full admin privileges
                            else:
                                # print(f"[INFO] Policy {policy_name} does not grant full administrative privileges (*:*).")
                                pass  # Optional: You can choose to remove this line or keep it as a placeholder
                else:
                    # print(f"[INFO] Policy {policy_name} is not an AWS-managed policy, skipping.")
                    pass  # Optional: You can choose to remove this line or keep it as a placeholder

        # Determine report status based on findings
        if findings:
            report.status = ResourceStatus.FAILED  # Indicate that the check failed
            report.resource_ids_status = {user['UserName']: False for user in users}  # Mark users as having issues
            report.report_metadata = {"findings": findings}  # Store findings in report metadata
            # print(f"[FAIL] Administrative privileges found for {len(findings)} policies.")
        else:
            report.status = ResourceStatus.PASSED  # Indicate that the check passed
            report.resource_ids_status = {user['UserName']: True for user in users}  # Mark all users as having no issues
            # print("[PASS] No administrative privileges found in AWS-managed policies.")

        return report


# The check will pass if no users have attached AWS-managed policies that grant full administrative privileges (*: * or AdministratorAccess).

# It will fail if any user has an attached AWS-managed policy that grants full administrative privileges, such as the AdministratorAccess policy or any policy with *: * actions.