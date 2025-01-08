"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: IAM Account Security Contact Information
Description: Verifies if AWS account has registered security contact information
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_account_security_contact_information_registered(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def validate_security_contact(self, account_client) -> tuple:
        """
        Validate AWS account security contact information
        Args:
            account_client: AWS Account client
        Returns:
            tuple: (is_compliant: bool, message: str)
        """
        try:
            response = account_client.get_alternate_contact(AlternateContactType='SECURITY')
            contact = response.get('AlternateContact', {})
            
            # Check for required fields
            email = contact.get('EmailAddress', '').strip()
            phone = contact.get('PhoneNumber', '').strip()
            name = contact.get('Name', '').strip()
            title = contact.get('Title', '').strip()
            
            if all([email, phone, name, title]):
                return True, "Security contact properly configured"
            
            missing = []
            if not email:
                missing.append("email")
            if not phone:
                missing.append("phone")
            if not name:
                missing.append("name")
            if not title:
                missing.append("title")
                
            return False, f"Incomplete security contact: missing {', '.join(missing)}"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False, "Security contact not configured"
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the security contact information check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            account = connection.client('account')
            is_compliant, message = self.validate_security_contact(account)
            
            report.passed = is_compliant
            report.resource_ids_status[message] = is_compliant

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
