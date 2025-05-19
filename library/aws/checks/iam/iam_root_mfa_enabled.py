"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import time
import boto3
import botocore.exceptions
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_root_mfa_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        report.resource_ids_status = []

        try:
            # Wait for the credential report to be ready
            for _ in range(10):  # Retry up to 10 times (approx 30 seconds max wait time)
                response = client.generate_credential_report()
                state = response["State"]
                if state == "COMPLETE":
                    break
                time.sleep(3)  # Wait before retrying
            else:
                raise ValueError("Credential report generation timed out.")

            # Step 2: Retrieve the credential report
            response = client.get_credential_report()["Content"]
            decoded_report = response.decode("utf-8").splitlines()

            # Step 3: Validate and parse the credential report
            if len(decoded_report) < 2:
                raise ValueError("Credential report is empty or invalid.")

            headers = decoded_report[0].split(',')
            rows = decoded_report[1:]

            # Find required column indexes
            mfa_active_idx = headers.index("mfa_active") if "mfa_active" in headers else -1

            # Step 4: Process each row to find the root account
            for row in rows:
                user_info = row.split(',')

                if user_info[0] == "<root_account>":
                    mfa_active = user_info[mfa_active_idx].strip().lower() if mfa_active_idx != -1 else "false"

                    if mfa_active == "true":
                        report.status = CheckStatus.PASSED
                        summary = "Root account has MFA enabled."
                    else:
                        report.status = CheckStatus.FAILED
                        summary = "Root account does NOT have MFA enabled. Immediate action recommended."

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name="RootAccount"),
                            status=report.status,
                            summary=summary
                        )
                    )
                    break  # Stop processing after the root account

        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError, ValueError) as e:
            # Set status to UNKNOWN when API call fails
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="RootAccount"),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to generate or retrieve IAM credential report.",
                    exception=str(e)
                )
            )

        return report
