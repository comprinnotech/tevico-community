"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class dynamodb_tables_kms_cmk_encryption_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize clients
        dynamodb_client = connection.client('dynamodb')
        kms_client = connection.client('kms')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Pagination to list all DynamoDB tables
            paginator = dynamodb_client.get_paginator('list_tables')

            for page in paginator.paginate():
                table_names = page.get('TableNames', [])

                for table_name in table_names:
                    try:
                        # Describe the table
                        table_desc = dynamodb_client.describe_table(TableName=table_name)['Table']

                        # Retrieve the encryption settings
                        sse_description = table_desc.get('SSEDescription', {})
                        encryption_status = sse_description.get('Status')
                        kms_key_arn = sse_description.get('KMSMasterKeyArn')

                        # Check if encryption is enabled and using a CMK
                        if encryption_status == 'ENABLED' and kms_key_arn:
                            key_metadata = kms_client.describe_key(KeyId=kms_key_arn)['KeyMetadata']

                            if key_metadata.get('KeyManager') == 'CUSTOMER':
                                # CMK encryption is enabled
                                report.resource_ids_status[f"{table_name} is encrypted with a CMK."] = True
                            else:
                                # Not using a CMK
                                report.resource_ids_status[f"{table_name} is encrypted but not with a CMK."] = False
                                report.status = ResourceStatus.FAILED
                        else:
                            # No encryption or not using a CMK
                            report.resource_ids_status[f"{table_name} has no CMK encryption enabled."] = False
                            report.status = ResourceStatus.FAILED

                    except dynamodb_client.exceptions.ResourceNotFoundException:
                        report.resource_ids_status[f"{table_name} does not exist."] = False
                        report.status = ResourceStatus.FAILED
                    except kms_client.exceptions.NotFoundException:
                        report.resource_ids_status[f"KMS key for {table_name} not found."] = False
                        report.status = ResourceStatus.FAILED
                    except Exception as e:
                        report.resource_ids_status[f"Error processing {table_name}: {str(e)}"] = False
                        report.status = ResourceStatus.FAILED

        except Exception as e:
            report.resource_ids_status["DynamoDB table listing error occurred."] = False
            report.status = ResourceStatus.FAILED

        return report
