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
            # Pagination to list all DynamoDB tables
            paginator = dynamodb_client.get_paginator('list_tables')

            for page in paginator.paginate():
                table_names = page.get('TableNames', [])

                for table_name in table_names:
                    
                    # Describe the table
                    table_desc = dynamodb_client.describe_table(TableName=table_name)['Table']
                    resource = AwsResource(arn=table_desc.get('TableArn'))

                    try:
                        
                        # Retrieve the encryption settings
                        sse_description = table_desc.get('SSEDescription', {})
                        encryption_status = sse_description.get('Status')
                        kms_key_arn = sse_description.get('KMSMasterKeyArn')

                        if encryption_status == 'ENABLED' and kms_key_arn:
                            key_metadata = kms_client.describe_key(KeyId=kms_key_arn)['KeyMetadata']

                            if key_metadata.get('KeyManager') == 'CUSTOMER':
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=resource,
                                        status=CheckStatus.PASSED,
                                        summary=f"DynamoDB table {table_name} is encrypted with a CMK."
                                    )
                                )
                            else:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=resource,
                                        status=CheckStatus.FAILED,
                                        summary=f"DynamoDB table {table_name} is encrypted with an AWS managed key."
                                    )
                                )
                                report.status = CheckStatus.FAILED
                        else:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.FAILED,
                                    summary=f"DynamoDB table {table_name} is encrypted with an Amazon DynamoDB owned key."
                                )
                            )
                            report.status = CheckStatus.FAILED

                    except Exception as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Error processing DynamoDB table {table_name}: {str(e)}",
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
                        summary="No DynamoDB tables found."
                    )
                )

        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(resource=""),
                    status=CheckStatus.FAILED,
                    summary=f"DynamoDB table listing error occurred: {str(e)}",
                    exception=e
                )
            )
            report.status = CheckStatus.FAILED
            
        return report
