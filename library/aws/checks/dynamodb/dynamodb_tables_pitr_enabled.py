"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-02-05
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check


class dynamodb_tables_pitr_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('dynamodb')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            table_names = []
            next_token = None

            # Fetch all DynamoDB tables using pagination
            while True:
                response = client.list_tables(ExclusiveStartTableName=next_token) if next_token else client.list_tables()
                table_names.extend(response.get("TableNames", []))
                next_token = response.get("LastEvaluatedTableName")
                if not next_token:
                    break  # Exit loop when no more pages

            if not table_names:
                # No DynamoDB tables found, mark as NOT_APPLICABLE
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No DynamoDB tables found."
                    )
                )
                return report

            for table_name in table_names:
                # Describe the table to get ARN
                table_desc = client.describe_table(TableName=table_name)["Table"]
                resource = AwsResource(arn=table_desc.get("TableArn"))

                try:
                    
                    # Check Point-in-Time Recovery (PITR) status
                    response = client.describe_continuous_backups(TableName=table_name)
                    pitr_status = response["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]

                    if pitr_status == "ENABLED":
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"DynamoDB table {table_name} has PITR enabled."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"DynamoDB table {table_name} has PITR disabled."
                            )
                        )


                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error describing DynamoDB table {table_name}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error listing DynamoDB tables: {str(e)}",
                    exception=str(e)
                )
            )

        return report
