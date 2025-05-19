"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-14
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class inspector_lambda_standard_scan_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED
        report.resource_ids_status = []

        try:
            client = connection.client("inspector2")
            sts = connection.client("sts")
            account_id = sts.get_caller_identity()["Account"]

            # Call batch_get_account_status with the current account ID
            response = client.batch_get_account_status(accountIds=[account_id])
            accounts = response.get("accounts", [])

            account_status = accounts[0]
            lambda_status = account_status.get("resourceState", {}).get("lambda", {}).get("status")

            if lambda_status == "ENABLED":
                status = CheckStatus.PASSED
                summary = "Inspector Lambda standard scan is enabled."
            elif lambda_status == "DISABLED":
                status = CheckStatus.FAILED
                summary = "Inspector Lambda standard scan is not enabled."
            elif lambda_status == "SUSPENDED":
                status = CheckStatus.FAILED
                summary = "Inspector Lambda standard scan is suspended."
            else:
                status = CheckStatus.UNKNOWN
                summary = f"Inspector Lambda standard scan is in transitional state: {lambda_status}."

            report.status = status
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=status,
                    summary=summary
                )
            )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking Inspector Lambda scan status: {str(e)}",
                    exception=str(e)
                )
            )

        return report
