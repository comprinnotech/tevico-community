import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_no_root_access_keys(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless root access keys are found
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Get access keys for the root account
            response = client.list_access_keys(UserName='root')
            access_keys = response.get('AccessKeyMetadata', [])

            if access_keys:
                # If access keys exist for the root account, report failure
                report.passed = False
                key_ids = [key['AccessKeyId'] for key in access_keys]
                report.resource_ids_status[f"Root account is using access keys [{', '.join(key_ids)}] "] = False
            else:
                # No access keys found for the root account
                report.resource_ids_status["Root account is NOT using access keys"] = True

        except client.exceptions.NoSuchEntityException:
            # If the root account does not have access keys, pass the check
            report.resource_ids_status["Root account is NOT using access keys"] = True
        except Exception as e:
            # Handle unexpected errors
            logging.error(f"Error while checking root access keys: {e}")
            report.passed = False
            report.resource_ids_status = {}

        return report
