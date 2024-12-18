"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class apigateway_execution_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('apigateway')
        report = CheckReport(name=__name__)
        report.passed = True
        try:
            # Retrieve all API Gateway REST APIs
            apis = client.get_rest_apis()
            
            for api in apis.get('items', []):
                api_id = api['id']
                api_name = api.get('name', 'Unnamed API')
                
                # Retrieve all stages for the current API
                stages = client.get_stages(restApiId=api_id)
                
                for stage in stages.get('item', []):
                    stage_name = stage['stageName']
                    resource_id = f"{api_name}/{stage_name}"
                    
                    # Default to False for any stage
                    report.resource_ids_status[resource_id] = False
                    
                    if 'methodSettings' in stage and stage['methodSettings']:
                        # If methodSettings exists but is empty, mark as failed
                        if not stage['methodSettings']:
                            report.passed = False
                            continue
                            
                        # Check if any method has logging enabled
                        logging_enabled = False
                        for key, settings in stage['methodSettings'].items():
                            if settings.get('loggingLevel') in ['ERROR', 'INFO']:
                                logging_enabled = True
                                break
                        
                        if logging_enabled:
                            report.resource_ids_status[resource_id] = True
                        else:
                            report.passed = False
                    else:
                        report.passed = False
        except Exception as e:
            report.passed = False

            
        return report
