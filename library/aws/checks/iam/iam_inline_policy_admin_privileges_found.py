"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11

Description: This code checks for AWS users who have too much power (administrative privileges) 
through their inline policies. It's like checking if any employees have unlimited access 
to all company resources when they should only have access to what they need for their job.
"""

import boto3
import logging
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Set up logging to track what's happening in our code
logger = logging.getLogger(__name__)

class iam_inline_policy_admin_privileges_found(Check):
    """
    This check looks for AWS users who might have too much power through their inline policies.
    Think of it like auditing employee access cards to make sure no one has unauthorized access to restricted areas.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Main function that checks for users with administrative privileges.
        
        Args:
            connection: Our secure connection to AWS
            
        Returns:
            report: A detailed report showing which users (if any) have too much access
        """
        # Start a new report - like opening a fresh security audit form
        report = CheckReport(name=__name__)
        
        # Step 1: Connect to AWS IAM (Identity and Access Management) service
        try:
            iam_client = connection.client('iam')
            logger.info("Successfully connected to AWS IAM service")
        except (BotoCoreError, ClientError) as e:
            # If we can't connect to AWS, log the error and return
            error_message = f"Cannot connect to AWS IAM service: {str(e)}"
            logger.error(error_message)
            report.passed = False
            report.report_metadata = {"error": error_message}
            return report

        # Step 2: Get list of all AWS users
        try:
            users = iam_client.list_users()['Users']
            logger.info(f"Found {len(users)} IAM users to check")
        except (BotoCoreError, ClientError) as e:
            error_message = f"Cannot get list of AWS users: {str(e)}"
            logger.error(error_message)
            report.passed = False
            report.report_metadata = {"error": error_message}
            return report

        # Lists to keep track of what we find
        findings = []  # Will store our security findings
        resource_ids_status = {}  # Will store status for each user

        # Step 3: Check each user's policies
        for user in users:
            user_name = user['UserName']
            logger.info(f"Checking policies for user: {user_name}")

            try:
                # Get list of user's inline policies
                inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
                logger.info(f"Found {len(inline_policies)} inline policies for user {user_name}")
            except (BotoCoreError, ClientError) as e:
                # If we can't get user's policies, mark as potential security risk
                error_message = f"Cannot check policies for user {user_name}: {str(e)}"
                logger.error(error_message)
                resource_ids_status[user_name] = False
                findings.append(error_message)
                continue

            # Flag to track if user has admin privileges
            has_admin_privileges = False

            # Step 4: Check each policy for administrative privileges
            for policy_name in inline_policies:
                try:
                    # Get the detailed policy rules
                    policy_document = iam_client.get_user_policy(
                        UserName=user_name, 
                        PolicyName=policy_name
                    )['PolicyDocument']
                except (BotoCoreError, ClientError) as e:
                    error_message = f"Cannot read policy {policy_name} for user {user_name}: {str(e)}"
                    logger.error(error_message)
                    findings.append(error_message)
                    continue

                # Step 5: Check if policy gives too much access
                if 'Statement' in policy_document:
                    for statement in policy_document['Statement']:
                        # Look for "Allow" permissions that might grant full access
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])

                            # Check if policy grants full access (using "*")
                            if (actions == "*" and resources == "*") or \
                               (isinstance(actions, list) and "*" in actions and 
                                isinstance(resources, list) and "*" in resources):
                                has_admin_privileges = True
                                finding = f"SECURITY ALERT: User {user_name} has full admin access through policy {policy_name}"
                                logger.warning(finding)
                                findings.append(finding)
                                break

            # Update user's security status
            resource_ids_status[user_name] = not has_admin_privileges

        # Step 6: Prepare final report
        if findings:
            # Some security issues were found
            report.passed = all(status for status in resource_ids_status.values())
            report.resource_ids_status = resource_ids_status
            report.report_metadata = {"findings": findings}
            logger.info(f"Check completed with {len(findings)} findings")
        else:
            # No security issues found
            report.passed = True
            report.resource_ids_status = {user['UserName']: True for user in users}
            logger.info("Check completed successfully - no security issues found")

        return report

# What this check does:
# 1. Passes (returns True) if:
#    - No users have full administrative access through inline policies
#    - All users have appropriate limited access
#
# 2. Fails (returns False) if:
#    - Any user has a policy giving them full access (using "*")
#    - We can't verify a user's policies (treating it as a security risk)
#
# Think of it like a security audit:
# - Looking for employees who might have "master keys" when they should only have specific access
# - Making sure everyone follows the "least privilege" principle (only having access to what they need)
