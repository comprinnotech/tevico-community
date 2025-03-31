"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-20
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class rds_instance_backup_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("rds")

            # Pagination for listing all RDS instances
            instances = []
            next_token = None

            while True:
                response = client.describe_db_instances(Marker=next_token) if next_token else client.describe_db_instances()
                instances.extend(response.get("DBInstances", []))
                next_token = response.get("Marker")

                if not next_token:
                    break

            # If no RDS instances exist, mark as NOT_APPLICABLE
            if not instances:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No RDS instances found.",
                    )
                )
                return report

            # Check each RDS instance for Backup Retention Period
            for instance in instances:
                instance_name = instance["DBInstanceIdentifier"]
                instance_arn = instance["DBInstanceArn"]
                try:
                    backup_retention_period = instance.get("BackupRetentionPeriod", 0)

                    if backup_retention_period > 0:
                        summary = f"Backup is enabled with retention period of {backup_retention_period} days for RDS instance {instance_name}."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"Backup is NOT enabled for RDS instance {instance_name}."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED  # At least one instance is non-compliant

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=instance_arn),
                            status=status,
                            summary=summary,
                        )
                    )
                except Exception as e:
                    # Handle AWS client errors
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=instance_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving backup retention details for {instance_name}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            # Handle AWS client errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving RDS instance details.",
                    exception=str(e),
                )
            )

        return report
