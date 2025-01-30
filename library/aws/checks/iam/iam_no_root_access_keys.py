"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_no_root_access_keys(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Default report status
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # List access keys for the root account
            response = client.list_access_keys(UserName='root')
            access_keys = response.get('AccessKeyMetadata', [])

            if access_keys:
                # Access keys found for the root account
                report.status = ResourceStatus.FAILED
                for key in access_keys:
                    access_key_id = key['AccessKeyId']
                    report.resource_ids_status[
                        f"Root account has active access key: {access_key_id}"
                    ] = False
            else:
                # No access keys found for the root account
                report.resource_ids_status[
                    "Root account is NOT using access keys"
                ] = True

        except client.exceptions.NoSuchEntityException:
            # Root account does not have access keys
            report.resource_ids_status[
                "Root account is NOT using access keys"
            ] = True

        except Exception as e:
            # Log unexpected errors and update report
            logging.error(f"Error while checking root access keys: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
