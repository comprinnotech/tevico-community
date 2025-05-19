"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-02-05
"""

import boto3

from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check

class efs_encryption_at_rest_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
        report.resource_ids_status = []

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
            
            # Check if no file systems are present
            if not file_systems:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EFS file systems found."
                    )
                )
                return report

            # Check encryption status for each file system
            for fs in file_systems:
                fs_id = fs['FileSystemId']
                fs_arn = fs['FileSystemArn']
                is_encrypted = fs.get('Encrypted', False)
                arn = fs.get('FileSystemArn')
                
                if is_encrypted:
                    resource_status = ResourceStatus(
                        resource=AwsResource(arn=arn),
                        status=CheckStatus.PASSED,
                        summary=f"EFS {fs_id} is encrypted at rest."
                    )
                else:
                    resource_status = ResourceStatus(
                        resource=AwsResource(arn=arn),
                        status=CheckStatus.FAILED,
                        summary=f"EFS {fs_id} is not encrypted at rest."
                    )
                    report.status = CheckStatus.FAILED

                report.resource_ids_status.append(resource_status)

        except Exception as e:
            # Handle unexpected errors
            error_status = ResourceStatus(
                resource=GeneralResource(name=""),
                status=CheckStatus.FAILED,
                summary=f"Unexpected error: {str(e)}"
            )
            report.resource_ids_status.append(error_status)
            report.status = CheckStatus.FAILED

        return report
