"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-1-16
"""

import boto3
import logging
from typing import List
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_account_maintain_current_contact_details(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report object
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Attributes to validate for account contact details
        required_fields: List[str] = [
            "full_name", "company_name", "address", "phone_number", "website_url"
        ]

        try:
            # Initialize the AWS Account client
            client = connection.client("account")

            # Fetch account contact information
            contact_info = client.get_contact_information()
            contact_details = contact_info.get("ContactInformation", {})

            # Extract and format required fields
            account_details = {
                "full_name": contact_details.get("FullName"),
                "phone_number": contact_details.get("PhoneNumber"),
                "company_name": contact_details.get("CompanyName"),
                "address": ", ".join(filter(None, [
                    contact_details.get("AddressLine1", ""),
                    contact_details.get("AddressLine2", ""),
                    contact_details.get("City", ""),
                    contact_details.get("StateOrRegion", ""),
                    contact_details.get("PostalCode", ""),
                    contact_details.get("CountryCode", ""),
                ])).strip(", "),
                "website_url": contact_details.get("WebsiteUrl"),
            }

            # Validate each required field
            for field in required_fields:
                if account_details.get(field):
                    report.resource_ids_status[f"{field} is updated"] = True
                else:
                    report.resource_ids_status[f"{field} is missing or outdated"] = False
                    report.status = ResourceStatus.FAILED

        except client.exceptions.NoSuchEntityException:
            # Handle the case where contact information is not available
            logging.error("No contact information found for this account.")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["No contact information found"] = False

        except Exception as e:
            # Handle unexpected errors
            logging.error(f"Error while checking account contact details: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["Error occurred while checking contact details"] = False

        return report
