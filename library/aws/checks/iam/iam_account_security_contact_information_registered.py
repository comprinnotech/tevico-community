"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class iam_account_security_contact_information_registered(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Checks if the security contact information is registered in AWS IAM account settings."""
        
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        # Initialize the AWS Account client
        account_client = connection.client('account')

        try:
            security_contact = account_client.get_alternate_contact(AlternateContactType='SECURITY')

            contact_info = security_contact['AlternateContact']
            required_fields = ['Name', 'Title', 'EmailAddress', 'PhoneNumber']
            missing_fields = [field for field in required_fields if not contact_info.get(field)]

            if not missing_fields:
                report.status = CheckStatus.PASSED
                summary = (f"Security contact is registered. "
                            f"Name: {contact_info['Name']}, "
                            f"Title: {contact_info['Title']}, "
                            f"Email: {contact_info['EmailAddress']}, "
                            f"Phone: {contact_info['PhoneNumber']}.")
            else:
                report.status = CheckStatus.FAILED
                summary = (f"Security contact is registered but missing fields: "
                            f"{', '.join(missing_fields)}.")

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='SECURITY_CONTACT'),
                    status=report.status,
                    summary=summary
                )
            )

        except account_client.exceptions.ResourceNotFoundException:
            # Raised if no security contact is set
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='SECURITY_CONTACT'),
                    status=CheckStatus.FAILED,
                    summary='No security contact is set for this AWS account.'
                )
            )

        except (ClientError, BotoCoreError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='SECURITY_CONTACT'),
                    status=CheckStatus.UNKNOWN,
                    summary='Failed to retrieve security contact due to an AWS API error.',
                    exception=str(e)
                )
            )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='SECURITY_CONTACT'),
                    status=CheckStatus.UNKNOWN,
                    summary='An unexpected error occurred while retrieving security contact information.',
                    exception=str(e)
                )
            )

        return report






