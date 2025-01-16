"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class apigateway_execution_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('apigateway')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Retrieve all API Gateway REST APIs
        apis = client.get_rest_apis()
        
        for api in apis.get('items', []):
            api_id = api['id']
            api_name = api.get('name', 'Unnamed API')
            
            # Retrieve all stages for the current API
            stages = client.get_stages(restApiId=api_id)
            
            # Check if each stage has logging enabled
            stage_passed = True
            for stage in stages.get('item', []):
                if 'methodSettings' in stage:
                    for key, settings in stage['methodSettings'].items():
                        if settings.get('loggingLevel') in ['ERROR', 'INFO']:
                            report.resource_ids_status[f"{api_name}-{stage['stageName']}"] = True
                        else:
                            report.resource_ids_status[f"{api_name}-{stage['stageName']}"] = False
                            stage_passed = False
                            report.status = ResourceStatus.FAILED
                else:
                    # No logging settings for this stage
                    report.resource_ids_status[f"{api_name}-{stage['stageName']}"] = False
                    stage_passed = False
                    report.status = ResourceStatus.FAILED
            
            # If any stage lacks logging, mark the API check as failed
            if not stage_passed:
                report.status = ResourceStatus.FAILED
        
        return report
