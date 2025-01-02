"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""


import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ssm_document_secrets_present(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            ssm_client = connection.client('ssm')

            # Get all SSM documents
            ssm_documents = ssm_client.list_documents()
            
            if not ssm_documents.get('DocumentIdentifiers'):
                report.resource_ids_status['No SSM documents found'] = False
                report.passed = False
                return report

            # Check each SSM document for proper secrets management
            for document in ssm_documents['DocumentIdentifiers']:
                document_name = document['Name']
                
                try:
                    document_details = ssm_client.describe_document(
                        Name=document_name
                    )
                    
                    document_content = document_details['Content']
                    has_secrets_management = ('SecretsManager' in document_content or 
                                           'ParameterStore' in document_content)
                    report.resource_ids_status[document_name] = has_secrets_management

                except (ClientError, BotoCoreError, Exception):
                    report.resource_ids_status[document_name] = False

            # Check passes only if all documents use proper secrets management
            report.passed = all(report.resource_ids_status.values())

        except (ClientError, BotoCoreError, Exception):
            report.resource_ids_status['Error checking SSM documents'] = False
            report.passed = False

        return report
