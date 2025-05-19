"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-09
"""

import boto3
import re
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ssm_document_secrets_present(Check):
    # Precompile regex patterns for better performance
    # Patterns for secure references according to AWS documentation
    SECURE_REF_PATTERN = re.compile(
        r'(?i)('
        # AWS Systems Manager Parameter Store references
        r'{{ssm:[^}]+}}|'
        r'{{ssm-secure:[^}]+}}|'
        r'{{resolve:ssm:[^}]+(?::[^}]+)?}}|'
        r'{{resolve:ssm-secure:[^}]+(?::[^}]+)?}}|'
        # AWS Secrets Manager references
        r'{{secretsmanager:[^}]+(?::[^}]+){0,3}}}|'
        r'{{resolve:secretsmanager:[^}]+(?::[^}]+){0,3}}}|'
        # AWS Parameter Store API references
        r'GetParameter\(|'
        r'GetParameters\(|'
        r'GetParametersByPath\(|'
        # AWS Secrets Manager API references
        r'GetSecretValue\(|'
        # General references to secure services
        r'SecretsManager|'
        r'ParameterStore|'
        r'aws:ssm|'
        r'aws:secretsmanager'
        r')'
    )
    
    # Pattern for detecting if a document might need secrets
    SECRET_NEED_PATTERN = re.compile(
        r'(?i)('
        # Common secret-related keywords
        r'password|'
        r'secret|'
        r'credential|'
        r'token|'
        r'key|'
        r'auth|'
        r'certificate|'
        r'private[\s_-]?key|'
        # Database connection strings
        r'connection[\s_-]?string|'
        r'jdbc|'
        r'mongodb(\+srv)?://|'
        r'postgres(ql)?://|'
        r'mysql://|'
        r'sqlserver://|'
        r'oracle://|'
        # API and authentication references
        r'api[\s_-]?key|'
        r'access[\s_-]?key|'
        r'client[\s_-]?id|'
        r'client[\s_-]?secret|'
        r'bearer|'
        r'oauth|'
        # Common AWS credential patterns
        r'aws_access_key_id|'
        r'aws_secret_access_key|'
        r'aws_session_token|'
        # Potential hardcoded secrets (long alphanumeric strings)
        r'[A-Za-z0-9+/]{32,}|'  # Base64-like strings
        r'[A-Za-z0-9]{32,}'     # Long alphanumeric strings
        r')'
    )
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ssm_client = connection.client('ssm')
        
        try:
            # Get all SSM documents using pagination
            ssm_documents = self._get_all_ssm_documents(ssm_client)
            
            if not ssm_documents:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No SSM documents found."
                    )
                )
                return report
            
            # Process each document
            documents_needing_secure_refs = []
            for document in ssm_documents:
                self._process_document(
                    document, 
                    ssm_client, 
                    report, 
                    documents_needing_secure_refs
                )
            
                
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving SSM documents.",
                    exception=str(e)
                )
            )
        
        return report
    
    def _get_all_ssm_documents(self, ssm_client):
        """Get all SSM documents using pagination."""
        ssm_documents = []
        paginator = ssm_client.get_paginator('list_documents')
        
        for page in paginator.paginate():
            ssm_documents.extend(page.get('DocumentIdentifiers', []))
            
        return ssm_documents
    
    def _process_document(self, document, ssm_client, report, documents_needing_secure_refs):
        """Process a single SSM document."""
        document_name = document['Name']
        
        try:
            # Get document content
            document_details = ssm_client.describe_document(Name=document_name)
            document_content = document_details.get('Content', '')
            
            # Check if document uses secure methods for secrets
            has_secure_refs = bool(self.SECURE_REF_PATTERN.search(document_content))
            
            # Check if document appears to need secrets
            needs_secrets = bool(self.SECRET_NEED_PATTERN.search(document_content))
            
            # Determine status and summary based on findings
            if needs_secrets:
                if has_secure_refs:
                    status = CheckStatus.PASSED
                    summary = f"SSM document '{document_name}' properly uses secure methods for secrets."
                else:
                    status = CheckStatus.FAILED
                    summary = f"SSM document '{document_name}' appears to need secrets but doesn't use secure references."
                    documents_needing_secure_refs.append(document_name)
            else:
                status = CheckStatus.NOT_APPLICABLE
                summary = f"SSM document '{document_name}' doesn't appear to require secrets."
            
            # Add result to report
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=document_name),
                    status=status,
                    summary=summary
                )
            )
                
        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=document_name),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving SSM document '{document_name}'.",
                    exception=str(e)
                )
            )
