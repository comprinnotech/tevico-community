"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: IAM Attached Policy Admin Privileges
Description: Checks for IAM users with attached AWS managed admin policies
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_attached_policy_admin_privileges_found(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)
        # Only AWS managed admin policies to check
        self.admin_policies = [
            'arn:aws:iam::aws:policy/AdministratorAccess'
        ]

    def check_user_policies(self, iam_client, username: str) -> tuple:
        """
        Check for AWS managed admin policies
        Args:
            iam_client: IAM client
            username: IAM username
        Returns:
            tuple: (has_admin: bool, admin_policies: list)
        """
        try:
            admin_policies = []
            attached_policies = iam_client.list_attached_user_policies(
                UserName=username
            ).get('AttachedPolicies', [])

            # Check only AWS managed policies
            for policy in attached_policies:
                if (policy['PolicyArn'] in self.admin_policies or
                    'arn:aws:iam::aws:policy' in policy['PolicyArn'] and
                    ':*' in iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                    ['Policy']['Description']):
                    admin_policies.append(policy['PolicyName'])

            return bool(admin_policies), admin_policies

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return False, []
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the AWS managed admin policies check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            iam = connection.client('iam')
            users = iam.list_users().get('Users', [])

            if not users:
                report.resource_ids_status["No IAM users found"] = True
                return report

            for user in users:
                username = user['UserName']
                has_admin, admin_policies = self.check_user_policies(iam, username)
                
                if has_admin:
                    status_msg = f"User has AWS managed admin privileges in policy: {', '.join(admin_policies)}"
                    report.passed = False
                else:
                    status_msg = "User has no AWS managed admin privileges"
                
                report.resource_ids_status[f"{username} : {status_msg}"] = not has_admin

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
