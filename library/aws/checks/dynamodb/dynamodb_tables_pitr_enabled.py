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
            # Pagination to get all DynamoDB tables
            paginator = client.get_paginator('list_tables')

            for page in paginator.paginate():
                table_names = page.get('TableNames', [])

                for table_name in table_names:
                    # Describe the table to get ARN
                    table_desc = client.describe_table(TableName=table_name)['Table']
                    resource = AwsResource(arn=table_desc.get('TableArn'))
                    
                    try:

                        response = client.describe_continuous_backups(TableName=table_name)
                        pitr_status = response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus']
                        

                        if pitr_status == 'ENABLED':
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.PASSED,
                                    summary=f"DynamoDB table {table_name} has PITR enabled."
                                )
                            )
                        else:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.FAILED,
                                    summary=f"DynamoDB table {table_name} has PITR disabled."
                                )
                            )
                            report.status = CheckStatus.FAILED

                    except client.exceptions.ContinuousBackupsUnavailableException:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"DynamoDB table {table_name} has no continuous backups available."
                            )
                        )
                        report.status = CheckStatus.FAILED

                    except Exception as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Error checking PITR for {table_name}: {str(e)}",
                                exception=e
                            )
                        )
                        report.status = CheckStatus.FAILED

            if not report.resource_ids_status:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(resource=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No DynamoDB tables found in the account."
                    )
                )

        except Exception as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(resource=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error listing DynamoDB tables: {str(e)}",
                    exception=e
                )
            )

        return report
