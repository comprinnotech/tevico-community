"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-02-05
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check


class dynamodb_tables_kms_cmk_encryption_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize clients
        dynamodb_client = connection.client('dynamodb')
        kms_client = connection.client('kms')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            table_names = []
            next_token = None

            # Fetch all tables using pagination
            while True:
                response = dynamodb_client.list_tables(ExclusiveStartTableName=next_token) if next_token else dynamodb_client.list_tables()
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
                # Describe the table
                table_desc = dynamodb_client.describe_table(TableName=table_name)["Table"]
                resource = AwsResource(arn=table_desc.get("TableArn"))

                try:

                    # Retrieve the encryption settings
                    sse_description = table_desc.get("SSEDescription", {})
                    encryption_status = sse_description.get("Status")
                    kms_key_arn = sse_description.get("KMSMasterKeyArn")

                    if encryption_status == "ENABLED" and kms_key_arn:
                        key_metadata = kms_client.describe_key(KeyId=kms_key_arn)["KeyMetadata"]
                        key_manager = key_metadata.get("KeyManager")

                        if key_manager == "CUSTOMER":
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.PASSED,
                                    summary=f"DynamoDB table {table_name} is encrypted with a Customer Managed KMS Key."
                                )
                            )
                        else:
                            report.status = CheckStatus.FAILED
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.FAILED,
                                    summary=f"DynamoDB table {table_name} is encrypted with an AWS managed key."
                                )
                            )

                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"DynamoDB table {table_name} is encrypted with an Amazon DynamoDB owned key."
                            )
                        )

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error processing DynamoDB table {table_name}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"DynamoDB table listing error occurred: {str(e)}",
                    exception=str(e)
                )
            )

        return report
