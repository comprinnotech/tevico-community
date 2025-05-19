"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-10
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class guardduty_enabled_centralized(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED  # Default status is FAILED
        report.resource_ids_status = []
        
        try:
            client = connection.client("guardduty")
            sts_client = connection.client("sts")
            current_account_id = sts_client.get_caller_identity()["Account"]
            
            # Get all detectors
            detector_ids = []
            next_token = None
            while True:
                response = client.list_detectors(NextToken=next_token) if next_token else client.list_detectors()
                detector_ids.extend(response.get("DetectorIds", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break

            # If no detectors exist, mark check as FAILED
            if not detector_ids:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="GuardDuty is not enabled."
                    )
                )
                return report

            # Process each detector
            for detector_id in detector_ids:
                try:
                    # First check if detector is enabled
                    detector_info = client.get_detector(DetectorId=detector_id)
                    
                    if detector_info.get("Status") != "ENABLED":
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=""),
                                status=CheckStatus.FAILED,
                                summary=f"GuardDuty detector {detector_id} is not enabled."
                            )
                        )
                        continue
                    
                    # First try to determine if this is a member account
                    is_member = False
                    is_admin = False
                    
                    # Check if this account has an administrator account (meaning it's a member)
                    admin_response = client.get_administrator_account(DetectorId=detector_id)
                    
                    if admin_response and "Administrator" in admin_response:
                        admin_info = admin_response["Administrator"]
                        if admin_info.get("RelationshipStatus") == "Enabled":
                            admin_account_id = admin_info.get("AccountId")
                            report.status = CheckStatus.PASSED
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=""),
                                    status=CheckStatus.PASSED,
                                    summary=f"GuardDuty detector {detector_id} is centrally managed by administrator account {admin_account_id}."
                                )
                            )
                            is_member = True

                    
                    # If not a member, check if this is an administrator account
                    if not is_member:
                        try:
                            # Check if this account has member accounts (meaning it's an admin)
                            members_response = client.list_members(
                                DetectorId=detector_id,
                                OnlyAssociated="true"
                            )
                            
                            if members_response and "Members" in members_response and members_response["Members"]:
                                member_count = len(members_response["Members"])
                                report.status = CheckStatus.PASSED
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=detector_id),
                                        status=CheckStatus.PASSED,
                                        summary=f"GuardDuty detector {detector_id} is an administrator account with {member_count} member accounts."
                                    )
                                )
                                is_admin = True
                        except Exception:
                            report.status = CheckStatus.UNKNOWN
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=GeneralResource(name=""),
                                    status=CheckStatus.UNKNOWN,
                                    summary=f"An error occurred while checking member accounts for detector {detector_id}.",
                                )
                            )
                    
                    # If neither member nor admin, it's a standalone detector
                    if not is_member and not is_admin:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=""),
                                status=CheckStatus.FAILED,
                                summary=f"GuardDuty detector {detector_id} is enabled but not centrally managed."
                            )
                        )
                
                except Exception as e:
                    error_message = f"Error processing GuardDuty detector {detector_id}: {str(e)}"
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.UNKNOWN,
                            summary=error_message,
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            error_message = f"Error connecting to GuardDuty: {str(e)}"
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=error_message,
                    exception=str(e)
                )
            )

        return report
