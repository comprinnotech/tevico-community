"""
AUTHOR: Tevico Community
EMAIL: community@tevi.co
DATE: 2025-01-10
"""

from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import AzureError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class storage_account_secure_transfer(Check):
    def execute(self, connection: dict) -> CheckReport:
        """
        Check if Azure Storage Accounts have secure transfer (HTTPS) enabled
        """
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        
        try:
            credential = connection['credential']
            subscription_id = connection['subscription_id']
            
            storage_client = StorageManagementClient(credential, subscription_id)
            
            # Get all storage accounts
            storage_accounts = storage_client.storage_accounts.list()
            
            account_found = False
            for account in storage_accounts:
                account_found = True
                account_name = account.name
                
                # Check if secure transfer is enabled
                secure_transfer_enabled = account.enable_https_traffic_only
                
                if secure_transfer_enabled:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(
                                name=account_name,
                                arn=account.id
                            ),
                            status=CheckStatus.PASSED,
                            summary=f"Storage account '{account_name}' has secure transfer (HTTPS) enabled."
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(
                                name=account_name,
                                arn=account.id
                            ),
                            status=CheckStatus.FAILED,
                            summary=f"Storage account '{account_name}' does not have secure transfer (HTTPS) enabled."
                        )
                    )
            
            if not account_found:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="No Storage Accounts Found"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No storage accounts found in the subscription."
                    )
                )
                
        except AzureError as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Azure Storage Account Check"),
                    status=CheckStatus.ERRORED,
                    summary="Error checking storage account secure transfer status.",
                    exception=str(e)
                )
            )
        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Azure Storage Account Check"),
                    status=CheckStatus.UNKNOWN,
                    summary="Unexpected error occurred during storage account check.",
                    exception=str(e)
                )
            )

        return report
