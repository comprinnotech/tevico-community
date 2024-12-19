"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class apigatewayv2_api_access_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('apigatewayv2')
        report = CheckReport(name=__name__)
        report.passed = True
        
        # List all API Gateway V2 APIs
        apis = client.get_apis()
        
        for api in apis.get('Items', []):
            api_id = api['ApiId']
            api_name = api.get('Name', 'Unnamed API')
            
            # List all stages for the current API
            stages = client.get_stages(ApiId=api_id)
            
            # Assume check is passed unless a stage is missing logging
            stage_passed = True
            for stage in stages.get('Items', []):
                if 'AccessLogSettings' not in stage or not stage['AccessLogSettings'].get('DestinationArn'):
                    # Logging is not enabled for this stage
                    report.resource_ids_status[f"{api_name}/{stage['StageName']}"] = False
                    stage_passed = False
                    report.passed = False
                else:
                    # Logging is enabled for this stage
                    report.resource_ids_status[f"{api_name}/{stage['StageName']}"] = True
            
            # If any stage is missing logging, mark the API check as failed
            if not stage_passed:
                report.passed = False
        
        return report
