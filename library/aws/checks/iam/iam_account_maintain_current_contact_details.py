"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-17

Description: This code checks if your AWS account's contact information is complete and up-to-date.
Think of it like making sure a business card has all the necessary contact details filled in correctly.
"""

import boto3
import logging
from botocore.exceptions import BotoCoreError, ClientError
from typing import List, Dict
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Set up logging to keep track of what's happening (like a security camera recording events)
logger = logging.getLogger(__name__)

class iam_account_maintain_current_contact_details(Check):
    """
    This check is like a form validator that ensures all required contact information 
    is present in your AWS account, similar to validating a complete business contact form.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Main function that checks if all required contact information is present and valid.
        Like going through a checklist to make sure all important contact details are filled in.
        """
        # Start a new report (like opening a fresh checklist)
        report = CheckReport(name=__name__)

        # List of contact details we need to check (like required fields on a form)
        required_fields: List[str] = [
            'full_name',      # Person's complete name
            'company_name',   # Organization's name
            'address',        # Complete mailing address
            'phone_number',   # Contact phone number
            'website_url'     # Company website
        ]

        try:
            # Step 1: Connect to AWS Account service (like opening the contact database)
            logger.info("Attempting to connect to AWS Account service")
            try:
                client = connection.client('account')
                logger.info("Successfully connected to AWS Account service")
            except (BotoCoreError, ClientError) as e:
                error_msg = f"Cannot connect to AWS Account service: {str(e)}"
                logger.error(error_msg)
                raise ConnectionError(error_msg)

            # Step 2: Get the contact information (like retrieving a contact card)
            try:
                contact_info = client.get_contact_information()
                logger.info("Successfully retrieved contact information")
            except (BotoCoreError, ClientError) as e:
                error_msg = f"Failed to retrieve contact information: {str(e)}"
                logger.error(error_msg)
                raise

            # Step 3: Extract and organize contact details
            # (like copying information from a complex form to a simple one)
            contact_data = contact_info.get('ContactInformation', {})
            
            # Carefully build the complete address by combining all address parts
            address_parts = [
                contact_data.get('AddressLine1', ''),  # Street address
                contact_data.get('AddressLine2', ''),  # Apartment/Suite number
                contact_data.get('City', ''),          # City name
                contact_data.get('StateOrRegion', ''), # State or region
                contact_data.get('PostalCode', ''),    # ZIP or postal code
                contact_data.get('CountryCode', '')    # Country code
            ]
            # Remove empty parts and join with commas (like making a proper address string)
            full_address = ', '.join(part for part in address_parts if part)

            # Organize all contact details in one place (like filling out a contact form)
            account_details = {
                'full_name': contact_data.get('FullName'),
                'phone_number': contact_data.get('PhoneNumber'),
                'company_name': contact_data.get('CompanyName'),
                'address': full_address,
                'website_url': contact_data.get('WebsiteUrl')
            }

            # Step 4: Check if all required information is present
            # (like making sure no important fields are left blank)
            all_checks_passed = True  # Assume everything is complete until we find missing items
            missing_fields = []       # Keep track of what's missing

            # Check each required field (like going through a checklist)
            for field in required_fields:
                if not account_details.get(field):
                    # If field is missing or empty
                    logger.warning(f"Missing required field: {field}")
                    report.resource_ids_status[field] = False
                    all_checks_passed = False
                    missing_fields.append(field)
                else:
                    # If field is present and not empty
                    report.resource_ids_status[field] = True
                    logger.info(f"Field present: {field}")

            # Step 5: Prepare the final report (like writing up the results)
            report.passed = all_checks_passed

            # Add helpful information about what's missing or complete
            if not all_checks_passed:
                # If some information is missing
                report.report_metadata = {
                    "message": "Some contact information is missing or incomplete.",
                    "missing_fields": missing_fields,
                    "status": "INCOMPLETE",
                    "recommendation": "Please add the missing contact information"
                }
                logger.warning(f"Contact information incomplete. Missing: {', '.join(missing_fields)}")
            else:
                # If all information is present
                report.report_metadata = {
                    "message": "All contact information is complete and present.",
                    "status": "COMPLETE",
                    "recommendation": "No action needed"
                }
                logger.info("All contact information is complete")

        except client.exceptions.NoSuchEntityException as e:
            # Handle case when no contact information exists (like finding an empty contact card)
            error_msg = "No contact information found for this account"
            logger.error(f"{error_msg}: {str(e)}")
            report.passed = False
            report.report_metadata = {
                "error": error_msg,
                "exception": str(e),
                "status": "NOT_FOUND",
                "recommendation": "Please add contact information to your AWS account"
            }

        except client.exceptions.AccessDeniedException as e:
            # Handle case when we don't have permission to check (like being locked out)
            error_msg = "Not allowed to access contact information"
            logger.error(f"{error_msg}: {str(e)}")
            report.passed = False
            report.report_metadata = {
                "error": error_msg,
                "exception": str(e),
                "status": "ACCESS_DENIED",
                "recommendation": "Please check your permissions for accessing account information"
            }

        except (BotoCoreError, ClientError) as e:
            # Handle AWS-specific errors (like technical difficulties)
            error_msg = "Error while working with AWS services"
            logger.error(f"{error_msg}: {str(e)}")
            report.passed = False
            report.report_metadata = {
                "error": error_msg,
                "exception": str(e),
                "status": "AWS_ERROR",
                "recommendation": "Please try again or contact AWS support"
            }

        except Exception as e:
            # Handle any unexpected errors (like catching anything else that might go wrong)
            error_msg = "Unexpected error while checking contact information"
            logger.error(f"{error_msg}: {str(e)}")
            report.passed = False
            report.report_metadata = {
                "error": error_msg,
                "exception": str(e),
                "status": "UNKNOWN_ERROR",
                "recommendation": "Please check system logs for more details"
            }

        return report



# The check will return **True (passed)** if all required fields (`full_name`, `company_name`, `address`, `phone_number`, and `website_url`) are present and not empty.
  
# The check will return **False (failed)** if any of these fields are missing or empty, or if an error occurs while fetching the contact information.
