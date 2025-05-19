"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-15
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_root_hardware_mfa_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED
        report.resource_ids_status = []
        iam_client = connection.client("iam")

        try:
            #Check if MFA is enabled for the root account at all
            account_summary = iam_client.get_account_summary().get('SummaryMap', {})
            if account_summary.get('AccountMFAEnabled', 0) != 1:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary='MFA is not enabled for the root account.'
                    )
                )
                return report

            # Collect all virtual MFA devices using pagination
            virtual_mfa_devices = []
            next_token = None

            while True:
                response = iam_client.list_virtual_mfa_devices(Marker=next_token) if next_token else iam_client.list_virtual_mfa_devices()
                virtual_mfa_devices.extend(response.get("VirtualMFADevices", []))
                next_token = response.get("Marker")
                if not next_token:
                    break

            # Process virtual MFA devices to check if any is used by root
            for mfa_device in virtual_mfa_devices:
                user_arn = mfa_device.get("User", {}).get("Arn", "")
                if ":root" in user_arn:
                    # Root is using virtual MFA => Fail
                    report.status = CheckStatus.FAILED
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.FAILED,
                            summary='Root account is using virtual MFA.'
                        )
                    )
                    return report

            # If no virtual MFA device is associated with root, assume hardware MFA
            report.status = CheckStatus.PASSED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.PASSED,
                    summary='Root account is using hardware MFA.'
                )
            )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"An error occurred during execution: {str(e)}",
                    exception=str(e)
                )
            )

        return report

