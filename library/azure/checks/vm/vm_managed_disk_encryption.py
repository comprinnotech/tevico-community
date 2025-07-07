"""
AUTHOR: Tevico Community
EMAIL: community@tevi.co
DATE: 2025-01-10
"""

from azure.mgmt.compute import ComputeManagementClient
from azure.core.exceptions import AzureError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class vm_managed_disk_encryption(Check):
    def execute(self, connection: dict) -> CheckReport:
        """
        Check if Azure VMs have managed disk encryption enabled
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
                
                # Check if VM has encryption enabled on OS disk
                os_disk_encrypted = False
                data_disks_encrypted = True
                
                if vm.storage_profile and vm.storage_profile.os_disk:
                    os_disk = vm.storage_profile.os_disk
                    if (os_disk.encryption_settings and 
                        os_disk.encryption_settings.enabled):
                        os_disk_encrypted = True
                
                # Check data disks encryption
                if vm.storage_profile and vm.storage_profile.data_disks:
                    for data_disk in vm.storage_profile.data_disks:
                        if not (data_disk.encryption_settings and 
                               data_disk.encryption_settings.enabled):
                            data_disks_encrypted = False
                            break
                
                if os_disk_encrypted and data_disks_encrypted:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(
                                name=vm_name,
                                arn=vm.id
                            ),
                            status=CheckStatus.PASSED,
                            summary=f"VM '{vm_name}' has disk encryption enabled."
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
                            summary=f"VM '{vm_name}' does not have disk encryption enabled on all disks."
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
                    resource=GeneralResource(name="Azure VM Encryption Check"),
                    status=CheckStatus.ERRORED,
                    summary="Error checking VM disk encryption status.",
                    exception=str(e)
                )
            )
        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Azure VM Encryption Check"),
                    status=CheckStatus.UNKNOWN,
                    summary="Unexpected error occurred during VM encryption check.",
                    exception=str(e)
                )
            )

        return report
