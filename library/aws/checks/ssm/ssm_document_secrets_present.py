"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""


import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_document_secrets_present(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ssm_client = connection.client('ssm')
        
        
        ssm_documents = ssm_client.list_documents()['DocumentIdentifiers']
        
       
        missing_secrets = []

        for document in ssm_documents:
            document_name = document['Name']
            
            try:
                
                document_details = ssm_client.describe_document(Name=document_name)
                document_content = document_details['Content']
                
               
                if 'SecretsManager' in document_content or 'ParameterStore' in document_content:
                    missing_secrets.append(document_name)
            except Exception as e:
                report.resource_ids_status[document_name] = False
                report.status = ResourceStatus.FAILED
                continue

      
        if missing_secrets:
            report.status = ResourceStatus.FAILED
            report.resource_ids_status.update({doc: False for doc in missing_secrets})
        else:
            report.status = ResourceStatus.PASSED
        
        return report
