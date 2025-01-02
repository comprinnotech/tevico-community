# import boto3

# from tevico.engine.entities.report.check_model import CheckReport
# from tevico.engine.entities.check.check import Check


# class apigateway_restapi_logging_enabled(Check):

#     def execute(self, connection: boto3.Session) -> CheckReport:
#         report = CheckReport(name=__name__)
#         client = connection.client('apigateway')
#         apis = client.get_rest_apis()['items']
#         for api in apis:
#             api_name = api['name']
#             logging = api['endpointConfiguration']['types']
#             if 'REGIONAL' in logging:
#                 report.passed = True
#                 report.resource_ids_status[api_name] = True
#             else:
#                 report.passed = False
#                 report.resource_ids_status[api_name] = False
#         return report

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class apigateway_restapi_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('apigateway')
        
        try:
            # Get all REST APIs
            apis = client.get_rest_apis()['items']
            
            for api in apis:
                api_id = api['id']
                api_name = api['name']
                
                # Get all stages for each API
                stages = client.get_stages(restApiId=api_id)['item']
                
                for stage in stages:
                    stage_name = stage['stageName']
                    resource_id = f"{api_name}/{stage_name}"
                    
                    # Check if logging is enabled for the stage
                    method_settings = stage.get('methodSettings', {})
                    
                    # Check '*/*' method settings for logging
                    default_method = method_settings.get('*/*', {})
                    logging_enabled = default_method.get('loggingLevel') in ['ERROR', 'INFO']
                    
                    if logging_enabled:
                        report.passed = True
                        report.resource_ids_status[resource_id] = True
                    else:
                        report.passed = False
                        report.resource_ids_status[resource_id] = False
                        
            return report
            
        except Exception as e:
            report.passed = False
            return report
