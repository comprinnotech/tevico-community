"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class efs_encryption_at_rest_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('efs')
        paginator = client.get_paginator('describe_file_systems')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Paginate through all EFS file systems
        for page in paginator.paginate():
            file_systems = page['FileSystems']
            for fs in file_systems:
                fs_id = fs['FileSystemId']
                
                # Check if encryption at rest is enabled
                encryption_at_rest_enabled = fs.get('Encrypted', False)
                
                if encryption_at_rest_enabled:
                    # Encryption is enabled for this file system
                    report.resource_ids_status[fs_id] = True
                else:
                    # Encryption is not enabled; fail the check for this file system
                    report.resource_ids_status[fs_id] = False
                    report.status = ResourceStatus.FAILED

        return report