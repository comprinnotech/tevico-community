"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-07
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class dynamodb_tables_kms_cmk_encryption_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('dynamodb')
        paginator = client.get_paginator('list_tables')
        
        report = CheckReport(name=__name__)
        report.passed = True
        
        # List all DynamoDB tables
        for page in paginator.paginate():
            table_names = page['TableNames']
            for table_name in table_names:
                table_desc = client.describe_table(TableName=table_name)['Table']
                
                # Retrieve the encryption settings
                encryption_type = table_desc.get('SSEDescription', {}).get('Status')
                kms_key_arn = table_desc.get('SSEDescription', {}).get('KMSMasterKeyArn')
                
                if encryption_type == 'ENABLED' and kms_key_arn:
                    # If CMK encryption is enabled, mark it as passed
                    report.resource_ids_status[table_name] = True
                else:
                    # Otherwise, mark the check as failed for this table
                    report.resource_ids_status[table_name] = False
                    report.passed = False
        
        return report
