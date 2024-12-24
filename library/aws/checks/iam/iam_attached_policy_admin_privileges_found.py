"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11

Description: This code checks if any AWS users have too much power (administrative privileges) 
in their account. It's like checking if anyone has a master key that can open all doors 
when they should only have keys to specific rooms.
"""

import boto3
import logging
from botocore.exceptions import BotoCoreError, ClientError
from typing import Dict, List
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Set up logging to track what's happening (like a security camera recording events)
logger = logging.getLogger(__name__)

class iam_attached_policy_admin_privileges_found(Check):
    """
    This security check looks for users who might have too much access power.
    Think of it as checking who has master keys in a building when they should
    only have access to their specific areas.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Main function that checks user permissions.
        Like doing a security audit of who has access to what.
        """
        # Start a new security report
        report = CheckReport(name=__name__)
        findings: List[str] = []
        resource_status: Dict[str, bool] = {}

        try:
            # Step 1: Connect to AWS Security Service (IAM)
            logger.info("Connecting to AWS IAM service")
            try:
                iam_client = connection.client('iam')
            except (BotoCoreError, ClientError) as e:
                error_msg = f"Cannot connect to AWS IAM service: {str(e)}"
                logger.error(error_msg)
                raise ConnectionError(error_msg)

            # Step 2: Get list of all users (like getting a list of all employees)
            try:
                users = iam_client.list_users()['Users']
                logger.info(f"Found {len(users)} users to check")
            except (BotoCoreError, ClientError) as e:
                error_msg = f"Cannot get list of users: {str(e)}"
                logger.error(error_msg)
                raise

            # Step 3: Check each user's permissions
            for user in users:
                user_name = user['UserName']
                logger.info(f"Checking permissions for user: {user_name}")
                
                # Start with assuming the user has appropriate permissions
                resource_status[user_name] = True

                try:
                    # Get all policies attached to this user (like checking what keys they have)
                    policies = iam_client.list_attached_user_policies(
                        UserName=user_name
                    )['AttachedPolicies']

                    # Check each policy (like examining each key)
                    for policy in policies:
                        policy_arn = policy['PolicyArn']
                        
                        try:
                            # Get detailed policy information
                            policy_details = iam_client.get_policy(PolicyArn=policy_arn)
                            policy_name = policy_details['Policy']['PolicyName']

                            # Check if this is an AWS-managed policy
                            if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                                # First, check for the most powerful access
                                if policy_name == 'AdministratorAccess':
                                    warning_msg = (f"SECURITY ALERT: User {user_name} has "
                                                 "full administrative access (AdministratorAccess)")
                                    logger.warning(warning_msg)
                                    findings.append(warning_msg)
                                    resource_status[user_name] = False
                                    break  # No need to check further

                                # Check policy details for full access rights
                                try:
                                    policy_version = iam_client.get_policy_version(
                                        PolicyArn=policy_arn,
                                        VersionId=policy_details['Policy']['DefaultVersionId']
                                    )
                                    policy_document = policy_version['PolicyVersion']['Document']

                                    # Check for unlimited access permissions
                                    if 'Statement' in policy_document:
                                        for statement in policy_document['Statement']:
                                            if (statement.get('Effect') == 'Allow' and 
                                                '*:*' in statement.get('Action', [])):
                                                warning_msg = (f"SECURITY ALERT: User {user_name} has "
                                                             f"full access through policy {policy_name}")
                                                logger.warning(warning_msg)
                                                findings.append(warning_msg)
                                                resource_status[user_name] = False
                                                break

                                except (BotoCoreError, ClientError) as e:
                                    logger.error(f"Error checking policy version for {policy_name}: {str(e)}")
                                    continue

                        except (BotoCoreError, ClientError) as e:
                            logger.error(f"Error checking policy {policy_arn}: {str(e)}")
                            continue

                except (BotoCoreError, ClientError) as e:
                    logger.error(f"Error checking policies for user {user_name}: {str(e)}")
                    continue

            # Step 4: Prepare the final security report
            report.passed = not findings  # Pass if no security issues found
            report.resource_ids_status = resource_status
            
            if findings:
                report.report_metadata = {
                    "message": "Some users have excessive administrative privileges",
                    "findings": findings,
                    "recommendation": "Review and restrict administrative access"
                }
                logger.warning(f"Found {len(findings)} security issues")
            else:
                report.report_metadata = {
                    "message": "No users found with excessive administrative privileges",
                    "recommendation": "Continue monitoring access levels"
                }
                logger.info("Security check passed - no issues found")

        except Exception as e:
            # Handle any unexpected errors
            error_msg = f"Unexpected error during security check: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {
                "error": error_msg,
                "status": "ERROR",
                "recommendation": "Please check system logs for details"
            }

        return report



# The check will pass if no users have attached AWS-managed policies that grant full administrative privileges (*: * or AdministratorAccess).

# It will fail if any user has an attached AWS-managed policy that grants full administrative privileges, such as the AdministratorAccess policy or any policy with *: * actions.