"""
Test for IAM account maintain current contact details check.
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.iam.iam_account_maintain_current_contact_details import iam_account_maintain_current_contact_details
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestIamAccountMaintainCurrentContactDetails:
    """Test cases for IAM account maintain current contact details check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="iam_account_maintain_current_contact_details",
            CheckTitle="IAM Account Maintains Current Contact Details",
            CheckType=["security"],
            ServiceName="iam",
            SubServiceName="account",
            ResourceIdTemplate="account",
            Severity="medium",
            ResourceType="aws-account",
            Risk="Missing or outdated contact details could delay communication with AWS during critical events",
            RelatedUrl="https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws account update-contact-information --email-address contact@example.com",
                    Terraform="N/A",
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Update AWS account contact details to ensure timely communication.",
                    Url="https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html"
                )
            ),
            Description="Ensures the AWS account has up-to-date primary contact details.",
            Categories=["security", "operations"]
        )

        self.check = iam_account_maintain_current_contact_details(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

        # Simulate the AWS exception structure
        self.mock_client.exceptions = MagicMock()
        class ResourceNotFoundException(Exception): pass
        self.mock_client.exceptions.ResourceNotFoundException = ResourceNotFoundException

    def test_contact_details_present(self):
        self.mock_client.get_contact_information.return_value = {
            'ContactInformation': {
                'FullName': 'John Doe',
                'AddressLine1': '123 Main St',
                'PhoneNumber': '+1234567890',
                'CompanyName': 'ACME Corp',
                'WebsiteUrl': 'https://acme.example.com'
            }
        }

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Primary contact details are up-to-date" in summary

    def test_contact_details_missing_required_fields(self):
        self.mock_client.get_contact_information.return_value = {
            'ContactInformation': {
                'FullName': '',
                'AddressLine1': '',
                'PhoneNumber': '',
                'CompanyName': 'ACME Corp',
                'WebsiteUrl': 'https://acme.example.com'
            }
        }

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert "missing fields" in summary

    def test_contact_details_not_set(self):
        self.mock_client.get_contact_information.return_value = {
            'ContactInformation': {}
        }

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.FAILED
        assert "Primary contact information is NOT set"  in summary
        

    def test_no_contact_information_key(self):
        self.mock_client.get_contact_information.return_value = {}

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.FAILED
        assert "Primary contact information is NOT set" in summary

    def test_resource_not_found_exception(self):
        self.mock_client.get_contact_information.side_effect = self.mock_client.exceptions.ResourceNotFoundException()

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.FAILED
        assert "Primary contact information is NOT set" in summary

    def test_client_error(self):
        self.mock_client.get_contact_information.side_effect = ClientError(
            error_response={'Error': {'Code': 'AccessDenied', 'Message': 'You are not authorized'}},
            operation_name='GetContactInformation'
        )

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.FAILED
        assert "Failed to retrieve" in summary or "ClientError" in summary

    def test_unexpected_exception(self):
        self.mock_client.get_contact_information.side_effect = Exception("Unexpected error")

        report = self.check.execute(self.mock_session)
        summary = report.resource_ids_status[0].summary or ""

        assert report.status == CheckStatus.FAILED
        assert "unexpected error" in summary.lower()
