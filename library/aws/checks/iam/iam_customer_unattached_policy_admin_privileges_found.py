"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: IAM Customer Unattached Policy Admin Privileges
Description: Detects unattached customer-managed policies with administrative privileges
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_customer_unattached_policy_admin_privileges_found(Check):
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

    def get_unattached_policies(self, iam_client) -> list:
        """Get list of unattached customer managed policies"""
        try:
            all_policies = []
            paginator = iam_client.get_paginator('list_policies')
            
            # Only get customer managed policies (Scope='Local')
            for page in paginator.paginate(Scope='Local'):
                # Filter for unattached policies
                all_policies.extend([
                    policy for policy in page['Policies']
                    if policy['AttachmentCount'] == 0
                ])
            
            return all_policies
        except ClientError:
            return []

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Execute the unattached policy check"""
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            iam = connection.client('iam')
            unattached_policies = self.get_unattached_policies(iam)

            # Handle case when no unattached customer policies exist
            if not unattached_policies:
                report.resource_ids_status["No customer unattached policy found"] = True
                return report

            for policy in unattached_policies:
                try:
                    policy_version = iam.get_policy(
                        PolicyArn=policy['Arn']
                    )['Policy']['DefaultVersionId']
                    
                    policy_doc = iam.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy_version
                    )['PolicyVersion']['Document']

                    if self.has_admin_privileges(policy_doc):
                        report.passed = False
                        report.resource_ids_status[
                            f"{policy['PolicyName']} : Has AWS admin privileges"
                        ] = False
                    else:
                        report.resource_ids_status[
                            f"{policy['PolicyName']} : No AWS admin privileges"
                        ] = True

                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        report.resource_ids_status[
                            f"{policy['PolicyName']} : Error checking policy - {e.response['Error']['Code']}"
                        ] = False

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
