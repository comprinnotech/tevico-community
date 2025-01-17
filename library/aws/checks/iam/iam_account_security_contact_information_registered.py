"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-1-16
"""

import boto3
import logging
from typing import Optional
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_account_security_contact_information_registered(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report object
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Initialize the AWS Account client
            client = connection.client("account")

            # Fetch security contact information
            security_contact = client.get_alternate_contact(
                AlternateContactType="SECURITY"
            ).get("AlternateContact", {})
            print(security_contact)

            # Extract email and phone number
            security_email = security_contact.get("EmailAddress")
            security_phone_number = security_contact.get("PhoneNumber")

            # Validate the security contact email
            if security_email:
                report.resource_ids_status["Security contact email is registered"] = True
            else:
                report.resource_ids_status["Security contact email is missing"] = False
                report.status = ResourceStatus.FAILED

            # Validate the security contact phone number
            if security_phone_number:
                report.resource_ids_status[
                    "Security contact phone number is registered"
                ] = True
            else:
                report.resource_ids_status[
                    "Security contact phone number is missing"
                ] = False
                report.status = ResourceStatus.FAILED

        except client.exceptions.ResourceNotFoundException:
            # Handle case where no security contact is found
            logging.error("No security contact information found for this account.")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status[
                "No security contact information found"
            ] = False

        except client.exceptions.AccessDeniedException:
            # Handle insufficient permissions
            logging.error(
                "Access denied when trying to fetch security contact information."
            )
            report.status = ResourceStatus.FAILED
            report.resource_ids_status[
                "Access denied to fetch security contact information"
            ] = False

        except Exception as e:
            # Handle unexpected errors
            logging.error(f"Error while checking security contact information: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status[
                "Error occurred while checking security contact information"
            ] = False

        return report
