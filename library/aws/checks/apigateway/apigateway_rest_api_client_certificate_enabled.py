"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class apigateway_rest_api_client_certificate_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Checks if API Gateway REST APIs have client certificates enabled.
        """
        client = connection.client('apigateway')
        report = CheckReport(name=__name__)
        report.passed = True
        processed_apis = []
        
        try:
            # Use pagination to handle large number of APIs efficiently
            paginator = client.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                apis = page.get('items', [])
                processed_apis.extend(apis)
                
                for api in apis:
                    try:
                        api_id = api['id']
                        api_name = api.get('name', 'Unnamed API')
                        
                        try:
                            # Get stages directly since pagination is not supported
                            stages_response = client.get_stages(restApiId=api_id)
                            
                            # Process each stage in the response
                            for stage in stages_response.get('item', []):
                                try:
                                    stage_name = stage.get('stageName', 'unknown')
                                    
                                    # Check if client certificate is enabled for this stage
                                    has_cert = stage.get('clientCertificateId') is not None
                                    
                                    # Use formatted string for resource ID
                                    resource_id = f"{api_name}/{stage_name}"
                                    report.resource_ids_status[resource_id] = has_cert
                                    
                                    if not has_cert:
                                        report.passed = False
                                        
                                except (KeyError, Exception) as e:
                                    # Handle errors in processing individual stages
                                    resource_id = f"{api_name}/unknown"
                                    report.resource_ids_status[resource_id] = False
                                    report.passed = False
                                    
                        except (ClientError, BotoCoreError) as e:
                            # Handle errors in getting stages
                            report.resource_ids_status[api_name] = False
                            report.passed = False
                            
                    except KeyError:
                        # Handle missing API information
                        continue
                        
        except (ClientError, BotoCoreError) as e:
            # Handle errors in listing APIs
            # Mark all processed APIs as failed
            for api in processed_apis:
                try:
                    api_name = api.get('name', 'Unnamed API')
                    report.resource_ids_status[api_name] = False
                except (KeyError, Exception):
                    continue
            report.passed = False
            
        return report
