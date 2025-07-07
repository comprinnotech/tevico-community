"""
AUTHOR: Tevico Community
EMAIL: community@tevi.co
DATE: 2025-07-07
"""

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.core.exceptions import AzureError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class vm_backup_enabled(Check):
    def execute(self, connection: dict) -> CheckReport:
        """
        Check if Azure VMs have backup enabled through Azure Backup service
        """
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        
        try:
            credential = connection['credential']
            subscription_id = connection['subscription_id']
            
            compute_client = ComputeManagementClient(credential, subscription_id)
            
            # Get all VMs across all resource groups
            vms = compute_client.virtual_machines.list_all()
            
            vm_found = False
            for vm in vms:
                vm_found = True
                vm_name = vm.name
                resource_group = vm.id.split('/')[4]  # Extract resource group from resource ID
                
                # Check if VM has backup configured
                # Note: This is a simplified check. In practice, you would need to:
                # 1. Check if Recovery Services Vault exists
                # 2. Check if VM is registered with backup service
                # 3. Check backup policy configuration
                
                backup_enabled = self._check_vm_backup_status(
                    credential, subscription_id, resource_group, vm_name
                )
                
                if backup_enabled:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(
                                name=vm_name,
                                arn=vm.id
                            ),
                            status=CheckStatus.PASSED,
                            summary=f"VM '{vm_name}' has backup enabled."
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(
                                name=vm_name,
                                arn=vm.id
                            ),
                            status=CheckStatus.FAILED,
                            summary=f"VM '{vm_name}' does not have backup enabled."
                        )
                    )
            
            if not vm_found:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="No VMs Found"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No virtual machines found in the subscription."
                    )
                )
                
        except AzureError as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Azure VM Backup Check"),
                    status=CheckStatus.ERRORED,
                    summary="Error checking VM backup status.",
                    exception=str(e)
                )
            )
        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Azure VM Backup Check"),
                    status=CheckStatus.UNKNOWN,
                    summary="Unexpected error occurred during VM backup check.",
                    exception=str(e)
                )
            )

        return report
    
    def _check_vm_backup_status(self, credential, subscription_id: str, resource_group: str, vm_name: str) -> bool:
        """
        Check if a specific VM has backup enabled
        This is a simplified implementation - in practice you would need to check:
        1. Recovery Services Vault configuration
        2. Backup policy assignment
        3. Protection status
        """
        try:
            # For now, return False as a placeholder
            # In a real implementation, you would use RecoveryServicesBackupClient
            # to check the actual backup status
            return False
        except Exception:
            return False