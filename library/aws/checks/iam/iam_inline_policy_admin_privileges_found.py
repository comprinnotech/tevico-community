"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-11-07

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
    """
    Security check to identify AWS IAM users with administrative privileges in inline policies.
    """
    
    def __init__(self, metadata=None):
        """
        Initialize check with configuration parameters.
        """
        super().__init__(metadata)
        self._initialize_check_parameters()

    def _initialize_check_parameters(self):
        """
        Initialize internal check parameters and configurations.
        """
        self.error_messages = {
            'policy_not_found': 'Policy document not found',
            'invalid_statement': 'Invalid statement format',
            'api_error': 'AWS API error occurred',
            'parse_error': 'Error parsing policy document'
        }

    def _validate_statement_format(self, statement):
        """
        Validate the format of a policy statement.
        Returns True if statement has valid format, False otherwise.
        """
        return (isinstance(statement, dict) and 
                'Effect' in statement and 
                'Action' in statement and 
                ('Resource' in statement or 'NotResource' in statement))

    def _normalize_policy_elements(self, actions, resources):
        """
        Normalize policy elements to lists for consistent processing.
        """
        try:
            if actions == "*":
                norm_actions = ["*"]
            else:
                norm_actions = [actions] if isinstance(actions, str) else actions or []

            if resources == "*":
                norm_resources = ["*"]
            else:
                norm_resources = [resources] if isinstance(resources, str) else resources or []
                
            return norm_actions, norm_resources
        except Exception:
            return [], []

    def check_policy_for_admin_access(self, policy_document: dict) -> tuple:
        """
        Analyze policy document for administrative privileges.
        Returns (has_admin_access: bool, access_type: str)
        """
        try:
            if not policy_document or 'Statement' not in policy_document:
                return False, ""

            # Convert statement to list if it's a single statement
            statements = policy_document['Statement']
            if isinstance(statements, dict):
                statements = [statements]
            elif not isinstance(statements, list):
                return False, ""

            for statement in statements:
                if not self._validate_statement_format(statement):
                    continue

                if statement.get('Effect') != 'Allow':
                    continue

                actions = statement.get('Action', [])
                resources = statement.get('Resource', statement.get('NotResource', []))

                # Normalize to lists
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources

                # Check for admin access
                if '*' in actions and '*' in resources:
                    return True, "FullAdminAccess"

            return False, ""

        except Exception:
            return False, ""

    def _get_user_policy_status(self, iam_client, user_name):
        """
        Get detailed policy status for a user.
        """
        try:
            policy_response = iam_client.list_user_policies(UserName=user_name)
            inline_policies = policy_response.get('PolicyNames', [])

            if not inline_policies:
                # Return just the user name instead of "No inline policies found"
                return True, f"{user_name}"

            admin_policies = []
            non_admin_policies = []

            for policy_name in inline_policies:
                try:
                    policy_response = iam_client.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    
                    policy_document = policy_response.get('PolicyDocument')
                    if not policy_document:
                        continue

                    has_admin, admin_type = self.check_policy_for_admin_access(policy_document)
                    if has_admin:
                        admin_policies.append(f"{policy_name} ({admin_type})")
                    else:
                        non_admin_policies.append(policy_name)

                except ClientError:
                    continue

            # Return just the user name regardless of policy status
            if admin_policies:
                return False, f"{user_name}"
            elif non_admin_policies:
                return True, f"{user_name}"
            
            return True, f"{user_name}"

        except ClientError:
            return False, f"{user_name}"

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the security check across all IAM users.
        """
        report = CheckReport(name=__name__)
        report.passed = True
        findings = []

        try:
            iam_client = connection.client('iam')
            paginator = iam_client.get_paginator('list_users')

            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    is_compliant, status_message = self._get_user_policy_status(iam_client, user_name)
                    
                    # Store the status message with the user name
                    report.resource_ids_status[status_message] = is_compliant
                    
                    if not is_compliant:
                        report.passed = False
                        findings.append(status_message)

            if findings:
                report.report_metadata = {"findings": findings}

        except (BotoCoreError, ClientError) as e:
            report.passed = False
            report.resource_ids_status["AWSError"] = False
            report.report_metadata = {"error": str(e)}
        except Exception as e:
            report.passed = False
            report.resource_ids_status["UnexpectedError"] = False
            report.report_metadata = {"error": str(e)}

        return report