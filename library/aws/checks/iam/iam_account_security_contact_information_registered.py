"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-17
"""

import boto3
import logging
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ParamValidationError
)

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Set up logging for tracking code execution
logger = logging.getLogger(__name__)

class iam_account_security_contact_information_registered(Check):
    """
    This check verifies if AWS account has security contact information registered.
    It's a critical security requirement to have proper contact details set up.
    """

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Executes the security contact information check.
        
        Args:
            connection: AWS session for making API calls
            
        Returns:
            CheckReport: Results of the security contact check
        """
        # Initialize our report
        report = CheckReport(name=__name__)

        try:
            # Step 1: Create AWS Account client
            try:
                account_client = connection.client('account')
            except (BotoCoreError, ClientError) as e:
                logger.error(f"Failed to create AWS Account client: {str(e)}")
                report.passed = False
                report.resource_ids_status['SECURITY_CONTACT'] = False
                return report

            # Step 2: Check if security contact is registered
            try:
                # Get security contact information from AWS
                security_contact = account_client.get_alternate_contact(
                    AlternateContactType='SECURITY'
                )
                
                # Step 3: Validate the contact information
                if 'AlternateContact' in security_contact and security_contact['AlternateContact']:
                    # Contact exists and has information
                    logger.info("Security contact information found")
                    report.passed = True
                    report.resource_ids_status['SECURITY_CONTACT'] = True
                else:
                    # Contact exists but information is incomplete
                    logger.warning("Security contact information is incomplete")
                    report.passed = False
                    report.resource_ids_status['SECURITY_CONTACT'] = False

            except account_client.exceptions.ResourceNotFoundException:
                # No security contact is registered
                logger.warning("No security contact found")
                report.passed = False
                report.resource_ids_status['SECURITY_CONTACT'] = False

            except ParamValidationError as e:
                # Invalid parameters in the request
                logger.error(f"Parameter validation error: {str(e)}")
                report.passed = False
                report.resource_ids_status['SECURITY_CONTACT'] = False

            except ClientError as e:
                # AWS API error
                logger.error(f"AWS API error: {str(e)}")
                report.passed = False
                report.resource_ids_status['SECURITY_CONTACT'] = False

        except Exception as e:
            # Catch any unexpected errors
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            report.passed = False
            report.resource_ids_status['SECURITY_CONTACT'] = False

        return report

# What this check does:
# 1. Passes (True) if security contact is registered and has complete information
# 2. Fails (False) if:
#    - No security contact is registered
#    - Contact information is incomplete
#    - Any errors occur during the check
