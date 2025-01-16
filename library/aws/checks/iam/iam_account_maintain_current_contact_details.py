"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-17
"""

import boto3
from typing import List, Dict, Any
from datetime import datetime
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_account_maintain_current_contact_details(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        # print("Starting the account contact details check...")

        # List of attributes to check
        checks_to_perform: List[str] = [
            'full_name', 'company_name', 'address', 'phone_number', 'website_url'
        ]
        
        # print("Attributes to check:", checks_to_perform)

        # Get the current account information from AWS
        client = connection.client('account')

        try:
            # Fetch account contact details using the AWS Account API
            # print("Fetching account contact information...")
            contact_info = client.get_contact_information()
            # print("Contact information fetched successfully.")
            # print("Raw response:", contact_info)  # Debugging line
            
            # Extract relevant fields from the fetched information
            account_details = {
                'full_name': contact_info.get('ContactInformation', {}).get('FullName'),
                'phone_number': contact_info.get('ContactInformation', {}).get('PhoneNumber'),
                'company_name': contact_info.get('ContactInformation', {}).get('CompanyName'),
                'address': ', '.join([
                    contact_info.get('ContactInformation', {}).get('AddressLine1', ''),
                    contact_info.get('ContactInformation', {}).get('AddressLine2', ''),
                    contact_info.get('ContactInformation', {}).get('City', ''),
                    contact_info.get('ContactInformation', {}).get('StateOrRegion', ''),
                    contact_info.get('ContactInformation', {}).get('PostalCode', ''),
                    contact_info.get('ContactInformation', {}).get('CountryCode', '')
                ]).strip(', '),  # Concatenating address lines
                'website_url': contact_info.get('ContactInformation', {}).get('WebsiteUrl')  # Assuming there's a Website URL
            }

            # print("Account details retrieved:", account_details)

            # Verify if all required fields are filled
            all_checks_passed = True
            for check in checks_to_perform:
                if not account_details.get(check):
                    # print(f"Check failed: '{check}' is missing or empty.")
                    all_checks_passed = False
                    report.resource_ids_status[check] = False
                else:
                    # print(f"Check passed: '{check}' is present.")
                    report.resource_ids_status[check] = True

            # Set the final report status based on whether all checks passed
            if all_checks_passed:
                report.status = ResourceStatus.PASSED
            else:
                report.status = ResourceStatus.FAILED
            
            if report.status:
                # print("All checks passed successfully.")
                pass
            else:
                # print("Some checks failed.")
                pass

        except client.exceptions.NoSuchEntityException:
            # Handle the case where contact information cannot be found
            report.status = ResourceStatus.FAILED
            report.report_metadata = {"error": "No contact information found for this account"}
            # print("Error: No contact information found for this account.")
        
        except Exception as e:
            # Handle any other exceptions
            report.status = ResourceStatus.FAILED
            report.report_metadata = {"error": str(e)}
            # print(f"An unexpected error occurred: {e}")

        # print("Check execution completed.")
        return report
    

# The check will return **True (passed)** if all required fields (`full_name`, `company_name`, `address`, `phone_number`, and `website_url`) are present and not empty.
  
# The check will return **False (failed)** if any of these fields are missing or empty, or if an error occurs while fetching the contact information.
