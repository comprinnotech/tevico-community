"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_policy_allows_privilege_escalation(Check):
    def _check_policy_escalation(self, policy_document):
        """Check if policy allows privilege escalation."""
        try:
            for statement in policy_document.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue

                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                resource = statement.get('Resource', [])
                if isinstance(resource, str):
                    resource = [resource]

                # Check for dangerous combinations
                for action in actions:
                    # Full admin access
                    if action == '*' and '*' in resource:
                        return False
                    
                    # IAM-specific checks
                    if action.lower().startswith('iam:'):
                        # Full IAM access
                        if action == 'iam:*':
                            return False
                        
                        # Check for specific IAM actions that could lead to escalation
                        action_lower = action.lower()
                        if any(keyword in action_lower for keyword in ['create', 'put', 'attach', 'update']):
                            if '*' in resource or any('iam' in r.lower() for r in resource):
                                return False

            return True
        except Exception:
            return False  # Fail safe if there's an error parsing

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if any check fails
        
        try:
            iam_client = connection.client('iam')
            
            # Check managed policies
            managed_policies = iam_client.list_policies(Scope='Local')['Policies']
            for policy in managed_policies:
                try:
                    policy_arn = policy['Arn']
                    policy_name = policy['PolicyName']
                    
                    # Get policy version details
                    policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    policy_doc = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_version
                    )['PolicyVersion']['Document']
                    
                    status = self._check_policy_escalation(policy_doc)
                    report.resource_ids_status[f"managed/{policy_name}"] = status
                    if not status:
                        report.passed = False
                except (ClientError, BotoCoreError):
                    report.resource_ids_status[f"managed/{policy_name}"] = False
                    report.passed = False

            # Check inline policies
            users = iam_client.list_users()['Users']
            for user in users:
                username = user['UserName']
                policy_names = iam_client.list_user_policies(UserName=username)['PolicyNames']
                for policy_name in policy_names:
                    try:
                        policy_doc = iam_client.get_user_policy(
                            UserName=username,
                            PolicyName=policy_name
                        )['PolicyDocument']
                        
                        status = self._check_policy_escalation(policy_doc)
                        report.resource_ids_status[f"inline/{username}/{policy_name}"] = status
                        if not status:
                            report.passed = False
                    except (ClientError, BotoCoreError):
                        report.resource_ids_status[f"inline/{username}/{policy_name}"] = False
                        report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error checking IAM policies'] = False
            report.passed = False

        return report






































































































