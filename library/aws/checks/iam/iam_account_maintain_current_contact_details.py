"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4
"""
"""
Check: IAM Account Contact Details
Description: Verifies if AWS account maintains current contact details
Author: Your Name
Date: YYYY-MM-DD
"""

"""
Check: IAM Account Contact Details
Description: Verifies if AWS account maintains current contact details
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_account_maintain_current_contact_details(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def check_contact_info(self, account_client) -> dict:
        """
        Validate primary account contact information
        Args:
            account_client: AWS Account client
        Returns:
            dict: Status of contact information with formatted messages
        """
        try:
            contact_info = account_client.get_contact_information()['ContactInformation']
            status = {}

            # Check address fields
            address_fields = ['AddressLine1', 'City', 'PostalCode', 'CountryCode']
            has_complete_address = all(
                len(str(contact_info.get(field, ''))) > 0 
                for field in address_fields
            )
            status["Address: Complete" if has_complete_address else "Address: Incomplete"] = has_complete_address

            # Check other required fields with specific messages
            field_messages = {
                'CompanyName': 'CompanyName: Present and valid',
                'FullName': 'FullName: Present and valid',
                'PhoneNumber': 'PhoneNumber: Present and valid',
                'WebsiteUrl': 'WebsiteUrl: Present and valid'
            }

            for field, message in field_messages.items():
                field_value = str(contact_info.get(field, '')).strip()
                is_valid = len(field_value) > 0
                status[message if is_valid else f"{field}: Missing or invalid"] = is_valid

            return status
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationException':
                return {"Contact Information: Invalid or missing": False}
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the account contact details check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            account = connection.client('account')
            contact_status = self.check_contact_info(account)
            
            # Update report with contact status
            report.resource_ids_status.update(contact_status)
            report.passed = all(contact_status.values())

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report

