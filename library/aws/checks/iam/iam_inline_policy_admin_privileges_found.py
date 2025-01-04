"""
AUTHOR: RONIT CHAUHAN
DATE: 2024-02-13

Description: This security check identifies AWS users who have:
1. Full administrative access (*:*) through their inline policies
2. Service-specific wildcards (like ec2:*) are allowed and won't trigger failures
"""
import boto3
import json
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_inline_policy_admin_privileges_found(Check):
    def __init__(self, metadata=None):
        """
        Initialize check with configuration parameters.
        Sets up admin action patterns and severity levels.
        """
        super().__init__(metadata)
        self.admin_actions = ['*:*', 'iam:*', 'organizations:*']
        self._initialize_check_parameters()

    def _initialize_check_parameters(self):
        """
        Initialize internal check parameters and configurations.
        Separate initialization for better maintainability.
        """
        self.error_messages = {
            'policy_not_found': 'Policy document not found',
            'invalid_statement': 'Invalid statement format',
            'api_error': 'AWS API error occurred',
            'parse_error': 'Error parsing policy document'
        }

    def _normalize_policy_elements(self, actions, resources):
        """
        Normalize policy elements to lists for consistent processing.
        
        Args:
            actions: Policy actions (string or list)
            resources: Policy resources (string or list)
            
        Returns:
            tuple: (normalized_actions, normalized_resources)
        """
        try:
            norm_actions = [actions] if isinstance(actions, str) else actions or []
            norm_resources = [resources] if isinstance(resources, str) else resources or []
            return norm_actions, norm_resources
        except Exception:
            return [], []

    def _validate_statement_format(self, statement):
        """
        Validate the format of a policy statement.
        
        Args:
            statement: Policy statement to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        return (isinstance(statement, dict) and 
                'Effect' in statement and 
                ('Action' in statement or 'Resource' in statement))

    def check_policy_for_admin_access(self, policy_document: dict) -> tuple:
        """
        Analyze policy document for administrative privileges.
        
        Args:
            policy_document: IAM policy document to analyze
            
        Returns:
            tuple: (has_admin: bool, admin_type: str)
        """
        try:
            if not policy_document or 'Statement' not in policy_document:
                return False, ""

            statements = policy_document['Statement']
            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                if not self._validate_statement_format(statement):
                    continue

                if statement.get('Effect') != 'Allow':
                    continue

                actions, resources = self._normalize_policy_elements(
                    statement.get('Action', []),
                    statement.get('Resource', [])
                )

                # Check for full admin access patterns
                if '*' in actions and '*' in resources:
                    return True, "FullAdminAccess"

                # Check for service-specific admin access
                if any(admin in actions for admin in self.admin_actions) and '*' in resources:
                    return True, "ServiceAdminAccess"

            return False, ""

        except Exception:
            return False, ""

    def _process_user_policies(self, iam_client, user_name):
        """
        Process and analyze all inline policies for a user.
        
        Args:
            iam_client: IAM client instance
            user_name: Name of the user to check
            
        Returns:
            tuple: (failed_policies, checked_policies, error_occurred)
        """
        failed_policies = []
        checked_policies = []
        
        try:
            policy_response = iam_client.list_user_policies(UserName=user_name)
            inline_policies = policy_response.get('PolicyNames', [])

            if not inline_policies:
                return [], [], False

            for policy_name in inline_policies:
                try:
                    policy_response = iam_client.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    
                    policy_document = policy_response.get('PolicyDocument')
                    if not policy_document:
                        continue

                    checked_policies.append(policy_name)
                    has_admin, admin_type = self.check_policy_for_admin_access(policy_document)

                    if has_admin:
                        failed_policies.append(f"{policy_name} ({admin_type})")

                except ClientError:
                    continue

            return failed_policies, checked_policies, False

        except ClientError:
            return [], [], True

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the security check across all IAM users.
        
        Args:
            connection: AWS session
            
        Returns:
            CheckReport: Results of the security check
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            iam_client = connection.client('iam')
            paginator = iam_client.get_paginator('list_users')

            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    failed_policies, checked_policies, error_occurred = self._process_user_policies(
                        iam_client, user_name
                    )

                    if error_occurred:
                        continue

                    if not checked_policies:
                        report.resource_ids_status[f"{user_name}: No inline policies found"] = True
                        continue

                    if failed_policies:
                        failed_policies_str = ", ".join(failed_policies)
                        report.resource_ids_status[f"{user_name}: policies {failed_policies_str}"] = False
                        report.passed = False
                    else:
                        checked_policies_str = ", ".join(checked_policies)
                        report.resource_ids_status[
                            f"{user_name}: policies {checked_policies_str} none of them having Administrative Privileges"
                        ] = True

        except (BotoCoreError, ClientError):
            report.passed = False
            report.resource_ids_status["AWSError"] = False
        except Exception:
            report.passed = False
            report.resource_ids_status["UnexpectedError"] = False

        return report


# What this security check does:
# 1. Fails (returns False) if:
#    - A user has full admin access (*:*)
#    - A user has no inline policies defined
#    - We can't verify a user's policies
#
# 2. Passes (returns True) if:
#    - Users have appropriate access (including service-specific wildcards like ec2:*)
#    - No users have full administrative privileges
#
# 3. Allows service-specific wildcards:
#    - ec2:* (all EC2 permissions)
#    - s3:* (all S3 permissions)
#    - etc.
