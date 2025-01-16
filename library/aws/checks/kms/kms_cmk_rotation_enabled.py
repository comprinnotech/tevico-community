"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError

class kms_cmk_rotation_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('kms')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        try:
            paginator = client.get_paginator('list_keys')
            
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key['KeyId']
                    
                    # Get key details first to check if it's customer managed
                    try:
                        key_info = client.describe_key(KeyId=key_id)
                        key_manager = key_info['KeyMetadata'].get('KeyManager')
                        key_state = key_info['KeyMetadata'].get('KeyState')
                        
                        # Skip AWS managed keys and keys that are not enabled
                        if key_manager == 'AWS' or key_state != 'Enabled':
                            continue
                        
                    except ClientError:
                        # If we can't get key details, mark it as non-compliant
                        report.resource_ids_status[key_id] = False
                        report.status = ResourceStatus.FAILED
                        continue

                    # Check rotation status only for customer managed keys
                    try:
                        rotation_status = client.get_key_rotation_status(KeyId=key_id)
                        rotation_enabled = rotation_status.get('KeyRotationEnabled', False)
                        
                        report.resource_ids_status[key_id] = rotation_enabled
                        if not rotation_enabled:
                            report.status = ResourceStatus.FAILED
                            
                    except ClientError:
                        # If we can't check rotation status, mark as non-compliant
                        report.resource_ids_status[key_id] = False
                        report.status = ResourceStatus.FAILED
                        
        except (ClientError, Exception):
            report.status = ResourceStatus.FAILED
            
        return report
