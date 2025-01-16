"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError

class kms_cmk_are_used(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('kms')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.FAILED  # Start with False until we find at least one valid CMK
        
        try:
            paginator = client.get_paginator('list_keys')
            customer_managed_keys_found = ResourceStatus.FAILED
            
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key['KeyId']
                    
                    # Get key details first to check if it's customer managed
                    try:
                        key_info = client.describe_key(KeyId=key_id)
                        key_manager = key_info['KeyMetadata'].get('KeyManager')
                        key_state = key_info['KeyMetadata'].get('KeyState')
                        
                        # Only process customer managed keys
                        if key_manager != 'CUSTOMER':
                            continue
                        
                        # Check if the key is enabled
                        is_enabled = (key_state == 'Enabled')
                        report.resource_ids_status[key_id] = is_enabled
                        
                        if is_enabled:
                            customer_managed_keys_found = ResourceStatus.PASSED
                            
                    except ClientError:
                        # If we can't get key details, mark it as non-compliant
                        report.resource_ids_status[key_id] = False
                        continue
                        
            # Set overall check status based on finding at least one enabled CMK
            report.status = customer_managed_keys_found
                        
        except (ClientError, Exception):
            report.status = ResourceStatus.FAILED
            
        return report
