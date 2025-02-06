
"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus
from tevico.engine.entities.check.check import Check

class apigateway_rest_api_client_certificate_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('apigateway')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        
        try:
            # Use pagination to handle large number of APIs efficiently
            paginator = client.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                for api in page.get('items', []):
                    api_id = api['id']
                    api_name = api.get('name', 'Unnamed API')
                    
                    try:
                        # Get stages directly since pagination is not supported
                        stages_response = client.get_stages(restApiId=api_id)
                        
                        # Process each stage in the response
                        for stage in stages_response.get('item', []):
                            stage_name = stage.get('stageName', 'unknown')
                            
                            # Check if client certificate is enabled for this stage
                            has_cert = stage.get('clientCertificateId') is not None
                            
                            # Use formatted string for resource ID
                            resource_id = f"{api_name}-{stage_name}"
                            report.resource_ids_status[resource_id] = has_cert
                            
                            if not has_cert:
                                report.status = CheckStatus.FAILED
                                
                    except client.exceptions.ClientError as e:
                        report.status = CheckStatus.FAILED
                                
        except client.exceptions.ClientError as e:
            report.status = CheckStatus.FAILED
            
        return report
