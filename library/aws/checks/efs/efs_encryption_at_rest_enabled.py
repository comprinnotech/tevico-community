"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2025-1-4

This module checks if Amazon EFS (Elastic File System) has encryption at rest enabled.
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class efs_encryption_at_rest_enabled(Check):
    """Checks if EFS file systems have encryption at rest enabled."""

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the check for EFS encryption at rest.
        
        Args:
            connection: boto3 Session object
        
        Returns:
            CheckReport: Contains check results with pass/fail status
        """
        report = CheckReport(name=__name__)
        report.passed = True

        if not connection:
            report.error = "No valid AWS connection provided"
            report.passed = False
            return report

        try:
            client = connection.client('efs')
            file_systems = self._get_file_systems(client)
            
            if not file_systems:
                report.resource_ids_status["No EFS File Systems Found"] = True
                return report

            for fs in file_systems:
                resource_id = self._get_resource_identifier(fs)
                is_encrypted = fs.get('Encrypted', False)
                report.resource_ids_status[resource_id] = is_encrypted
                report.passed &= is_encrypted

        except ClientError as e:
            report.error = f"AWS API Error: {e.response['Error']['Message']}"
            report.passed = False
        except Exception as e:
            report.error = f"Unexpected error: {str(e)}"
            report.passed = False

        return report

    def _get_file_systems(self, client) -> list:
        """
        Retrieve EFS file systems using pagination.
        
        Args:
            client: boto3 EFS client
        
        Returns:
            list: List of file systems
        """
        try:
            file_systems = []
            paginator = client.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                file_systems.extend(page.get('FileSystems', []))
            return file_systems
        except ClientError:
            return []

    def _get_resource_identifier(self, fs: dict) -> str:
        """
        Create resource identifier string from file system metadata.
        
        Args:
            fs: File system dictionary
        
        Returns:
            str: Resource identifier in format 'name (fs-id)'
        """
        fs_id = fs.get('FileSystemId', 'Unknown')
        fs_name = 'unnamed-efs'
        
        for tag in fs.get('Tags', []):
            if tag.get('Key') == 'Name':
                fs_name = tag.get('Value')
                break
                
        return f"{fs_name} ({fs_id})"
