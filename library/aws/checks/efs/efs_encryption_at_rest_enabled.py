"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-24
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class efs_encryption_at_rest_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Initialize the EFS client
        client = connection.client('efs')

        try:
            # Pagination to get all file systems
            file_systems = []
            next_token = None

            while True:
                response = client.describe_file_systems(Marker=next_token) if next_token else client.describe_file_systems()
                file_systems.extend(response.get('FileSystems', []))
                next_token = response.get('NextMarker', None)

                if not next_token:
                    break

            # Check encryption status for each file system
            for fs in file_systems:
                fs_id = fs['FileSystemId']
                is_encrypted = fs.get('Encrypted', False)

                # Record the result for each file system
                if is_encrypted:
                    report.resource_ids_status[f"EFS {fs_id} is encrypted at rest."] = True
                else:
                    report.resource_ids_status[f"EFS {fs_id} is not encrypted at rest."] = False
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            # Handle unexpected errors
            report.resource_ids_status[f"Unexpected error: {str(e)}"] = False
            report.status = ResourceStatus.FAILED

        return report