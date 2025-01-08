"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: IAM Customer Attached Policy Admin Privileges
Description: Detects customer-managed policies with administrative privileges
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_customer_attached_policy_admin_privileges_found(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def has_admin_privileges(self, policy_doc: dict) -> bool:
        """Check if policy document contains admin privileges"""
        try:
            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            return any(
                stmt.get('Effect') == 'Allow' and
                (stmt.get('Action') == '*' or 
                 (isinstance(stmt.get('Action'), list) and '*' in stmt.get('Action'))) and
                (stmt.get('Resource') == '*' or 
                 (isinstance(stmt.get('Resource'), list) and '*' in stmt.get('Resource')))
                for stmt in statements
            )
        except Exception:
            return False

    def check_user_policies(self, iam_client, username: str) -> dict:
        """Check user's customer-managed attached policies for admin privileges"""
        try:
            attached_policies = iam_client.list_attached_user_policies(
                UserName=username
            ).get('AttachedPolicies', [])
            
            if not attached_policies:
                return {"status": "no_policies"}
            
            admin_policies = []
            for policy in attached_policies:
                try:
                    # Skip AWS managed policies
                    if 'arn:aws:iam::aws:policy/' in policy['PolicyArn']:
                        continue
                        
                    policy_version = iam_client.get_policy(
                        PolicyArn=policy['PolicyArn']
                    )['Policy']['DefaultVersionId']
                    
                    policy_doc = iam_client.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=policy_version
                    )['PolicyVersion']['Document']
                    
                    if self.has_admin_privileges(policy_doc):
                        admin_policies.append(policy['PolicyName'])
                except ClientError:
                    continue
            
            return {
                "status": "has_admin" if admin_policies else "no_admin",
                "policies": admin_policies
            }
            
        except ClientError:
            return {"status": "error"}

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Execute the customer-managed policy check"""
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            iam = connection.client('iam')
            users = iam.list_users().get('Users', [])

            # Handle case when no IAM users exist
            if not users:
                report.resource_ids_status["No IAM users found"] = True
                return report

            for user in users:
                username = user['UserName']
                result = self.check_user_policies(iam, username)
                
                if result["status"] == "no_policies":
                    status_msg = "No customer-managed policies attached"
                    status_value = True
                elif result["status"] == "has_admin":
                    status_msg = f"Has AWS admin privileges in customer-managed policies: {', '.join(result['policies'])}"
                    status_value = False
                    report.passed = False
                else:
                    status_msg = "No AWS admin privileges in customer-managed policies"
                    status_value = True
                
                report.resource_ids_status[f"{username} : {status_msg}"] = status_value

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
