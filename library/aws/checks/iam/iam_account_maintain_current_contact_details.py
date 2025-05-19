"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class iam_account_maintain_current_contact_details(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Checks if the AWS account maintains up-to-date primary contact details."""
        
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        # Initialize the AWS Account client
        account_client = connection.client('account')

        try:
            contact_info = account_client.get_contact_information()

            if 'ContactInformation' in contact_info and contact_info['ContactInformation']:
                contact_details = contact_info['ContactInformation']

                # Required fields
                required_fields = ['FullName', 'AddressLine1', 'PhoneNumber']
                missing_fields = [field for field in required_fields if not contact_details.get(field)]

                # Optional fields
                company_name = contact_details.get('CompanyName', 'N/A')
                website_url = contact_details.get('WebsiteUrl', 'N/A')

                if not missing_fields:
                    report.status = CheckStatus.PASSED
                    summary = (f"Primary contact details are up-to-date. "
                               f"Name: [{contact_details['FullName']}], "
                               f"Address: [{contact_details['AddressLine1']}], "
                               f"Phone: [{contact_details['PhoneNumber']}], "
                               f"Company: [{company_name}], "
                               f"Website: [{website_url}].")
                else:
                    report.status = CheckStatus.FAILED
                    summary = (f"Primary contact details are missing fields: {', '.join(missing_fields)}. "
                               f"Company: {company_name}, Website: {website_url}.")

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name='PRIMARY_CONTACT'),
                        status=report.status,
                        summary=summary
                    )
                )

            else:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name='PRIMARY_CONTACT'),
                        status=CheckStatus.FAILED,
                        summary='Primary contact information is NOT set for this AWS account.'
                    )
                )

        except account_client.exceptions.ResourceNotFoundException:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='PRIMARY_CONTACT'),
                    status=CheckStatus.FAILED,
                    summary='Primary contact information is NOT set for this AWS account.'
                )
            )

        except ClientError as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='PRIMARY_CONTACT'),
                    status=CheckStatus.FAILED,
                    summary='Failed to retrieve primary contact details due to an AWS ClientError.',
                    exception=str(e)
                )
            )

        except Exception as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='PRIMARY_CONTACT'),
                    status=CheckStatus.FAILED,
                    summary='An unexpected error occurred while retrieving primary contact details.',
                    exception=str(e)
                )
            )

        return report
