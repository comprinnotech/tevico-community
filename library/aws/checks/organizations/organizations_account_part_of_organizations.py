"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: AWS Organizations Account Membership
Description: Verifies if the AWS account is part of an AWS Organizations structure
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class organizations_account_part_of_organizations(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def check_organization_membership(self, org_client, sts_client) -> dict:
        """
        Check if account is part of AWS Organizations and get organization details
        Args:
            org_client: Organizations client
            sts_client: STS client
        Returns:
            dict: Organization status and details
        """
        try:
            org_info = org_client.describe_organization()['Organization']
            account_id = sts_client.get_caller_identity()['Account']
            
            # Format organization details into a single status message
            status_message = (
                f"({account_id}) account is part of organization {org_info['Id']} "
                f"(Master: {org_info['MasterAccountId']}, "
                f"Features: {org_info['FeatureSet']}, "
                f"Organization Status: Active)"
            )
            
            return {status_message: True}
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                return {"Account Status: Not part of AWS Organizations": False}
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the Organizations membership check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            org_client = connection.client('organizations')
            sts_client = connection.client('sts')
            org_status = self.check_organization_membership(org_client, sts_client)
            
            # Update report with organization status
            report.resource_ids_status.update(org_status)
            report.passed = all(org_status.values())

        except ClientError as e:
            report.passed = False
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                report.resource_ids_status["Access Denied: Insufficient permissions to check Organizations"] = False
            else:
                report.resource_ids_status[f"AWS Error: {error_code}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
