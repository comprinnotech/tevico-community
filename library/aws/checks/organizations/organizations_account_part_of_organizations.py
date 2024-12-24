"""
AUTHOR: RONIT CHAUHAN
DATE: 2024-10-17

Description: This program checks if your AWS account is part of an AWS Organization.
Think of it like checking if a branch office (AWS account) is properly connected to its headquarters (AWS Organization).
"""

import boto3  # AWS SDK for Python - helps us talk to AWS services
import logging  # For keeping track of what the program is doing
from botocore.exceptions import BotoCoreError, ClientError  # For handling AWS-specific errors
from tevico.engine.entities.report.check_model import CheckReport  # For creating our check report
from tevico.engine.entities.check.check import Check  # Base class for our check
from datetime import datetime  # For adding timestamps to our reports

# Set up logging - We only want to see errors, not debug messages
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

class organizations_account_part_of_organizations(Check):
    """
    This class is like a detective that investigates whether your AWS account
    is properly connected to an AWS Organization.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Main function that does the actual checking.
        Think of this as the detective's investigation process.

        Args:
            connection: Our secure line to AWS (like a special phone line)
        Returns:
            CheckReport: The detective's findings (pass/fail with details)
        """
        # Start our investigation report
        report = CheckReport(name=__name__)
        
        try:
            # Step 1: Try to connect to AWS Organizations
            # Like trying to call the headquarters
            try:
                org_client = connection.client('organizations')
            except (BotoCoreError, ClientError) as e:
                raise ConnectionError(f"Couldn't connect to AWS Organizations: {str(e)}")

            try:
                # Step 2: Try to get organization details
                # Like asking headquarters for information
                # We'll try up to 3 times if we get temporary failures
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        response = org_client.describe_organization()
                        break
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ThrottlingException':
                            retry_count += 1
                            if retry_count == max_retries:
                                raise
                            continue
                        raise

                # Step 3: Check if we got valid organization information
                if 'Organization' in response:
                    # Extract important details about the organization
                    org = response['Organization']
                    org_id = org.get('Id')  # Organization's ID number
                    org_arn = org.get('Arn')  # Organization's unique identifier
                    master_account_id = org.get('MasterAccountId')  # Main account ID
                    feature_set = org.get('FeatureSet')  # What features are enabled

                    # If we found an organization ID, everything is good
                    if org_id:
                        # Mark the check as passed
                        report.passed = True
                        report.resource_ids_status = {
                            org_id: True,
                            'organization_status': True
                        }
                        # Add detailed information to our report
                        report.report_metadata = {
                            "status": "PASS",
                            "message": f"AWS Organization {org_id} contains this AWS account",
                            "details": {
                                "organization_id": org_id,
                                "organization_arn": org_arn,
                                "master_account_id": master_account_id,
                                "feature_set": feature_set,
                                "region": connection.region_name,
                                "timestamp": datetime.now().isoformat()
                            }
                        }
                    else:
                        # No organization ID found - something's wrong
                        raise ValueError("Couldn't find the organization ID")

            # Handle the case where Organizations isn't being used
            except org_client.exceptions.AWSOrganizationsNotInUseException as e:
                report.passed = False
                report.resource_ids_status = {
                    'organization_status': False
                }
                report.report_metadata = {
                    "status": "FAIL",
                    "message": "This AWS Account isn't using AWS Organizations",
                    "details": {
                        "error": str(e),
                        "error_type": "OrganizationsNotInUse",
                        "recommendation": "Consider enabling AWS Organizations for better account management",
                        "timestamp": datetime.now().isoformat()
                    }
                }

        # Handle permission errors (like not having the right security clearance)
        except org_client.exceptions.AccessDeniedException as e:
            report.passed = False
            report.report_metadata = {
                "status": "ERROR",
                "message": "Not allowed to check organization status",
                "details": {
                    "error": str(e),
                    "error_type": "AccessDenied",
                    "required_permission": "organizations:DescribeOrganization",
                    "recommendation": "Check if you have permission to view organization details",
                    "timestamp": datetime.now().isoformat()
                }
            }

        # Handle AWS-specific errors
        except (BotoCoreError, ClientError) as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', 'Unknown')
            error_message = getattr(e, 'response', {}).get('Error', {}).get('Message', str(e))
            
            report.passed = False
            report.report_metadata = {
                "status": "ERROR",
                "message": "Problem accessing AWS Organizations",
                "details": {
                    "error": error_message,
                    "error_code": error_code,
                    "error_type": "AWSAPIError",
                    "region": connection.region_name,
                    "recommendation": self._get_error_recommendation(error_code),
                    "timestamp": datetime.now().isoformat()
                }
            }

        # Handle data validation errors
        except ValueError as e:
            report.passed = False
            report.report_metadata = {
                "status": "ERROR",
                "message": "Invalid organization information received",
                "details": {
                    "error": str(e),
                    "error_type": "ValidationError",
                    "recommendation": "Verify organization setup",
                    "timestamp": datetime.now().isoformat()
                }
            }

        # Handle any unexpected errors
        except Exception as e:
            report.passed = False
            report.report_metadata = {
                "status": "ERROR",
                "message": "Unexpected problem during check",
                "details": {
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "recommendation": "Contact technical support",
                    "timestamp": datetime.now().isoformat()
                }
            }

        return report

    def _get_error_recommendation(self, error_code: str) -> str:
        """
        Provides helpful suggestions based on the type of error we encountered.
        Like a troubleshooting guide for common problems.
        """
        recommendations = {
            "ThrottlingException": "Too many requests - try again more slowly",
            "InvalidInputException": "Check if organization settings are correct",
            "ServiceException": "AWS service issue - try again later",
            "TooManyRequestsException": "Slow down the request rate",
            "UnrecognizedClientException": "Check AWS credentials"
        }
        return recommendations.get(error_code, "Check AWS documentation for help")

    # Pass Condition: If the organization is ENABLED, it adds a "PASS" status confirming that the AWS Organization contains the AWS account.
    # Fail Condition: If the status is not "ENABLED", it adds a "FAIL" status that the AWS Organization is not in use.