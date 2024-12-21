# """
# AUTHOR: deepak-puri-comprinno
# EMAIL: deepak.puri@comprinno.net
# DATE: 2024-11-13
# """

# import boto3
# from tevico.engine.entities.report.check_model import CheckReport
# from tevico.engine.entities.check.check import Check

# class apigateway_execution_logging_enabled(Check):
#     def execute(self, connection: boto3.Session) -> CheckReport:
#         client = connection.client('apigateway')
#         report = CheckReport(name=__name__)
#         report.passed = True
#         try:
#             # Retrieve all API Gateway REST APIs
#             apis = client.get_rest_apis()
            
#             for api in apis.get('items', []):
#                 api_id = api['id']
#                 api_name = api.get('name', 'Unnamed API')
                
#                 # Retrieve all stages for the current API
#                 stages = client.get_stages(restApiId=api_id)
                
#                 for stage in stages.get('item', []):
#                     stage_name = stage['stageName']
#                     resource_id = f"{api_name}/{stage_name}"
                    
#                     # Default to False for any stage
#                     report.resource_ids_status[resource_id] = False
                    
#                     if 'methodSettings' in stage and stage['methodSettings']:
#                         # If methodSettings exists but is empty, mark as failed
#                         if not stage['methodSettings']:
#                             report.passed = False
#                             continue
                            
#                         # Check if any method has logging enabled
#                         logging_enabled = False
#                         for key, settings in stage['methodSettings'].items():
#                             if settings.get('loggingLevel') in ['ERROR', 'INFO']:
#                                 logging_enabled = True
#                                 break
                        
#                         if logging_enabled:
#                             report.resource_ids_status[resource_id] = True
#                         else:
#                             report.passed = False
#                     else:
#                         report.passed = False
#         except Exception as e:
#             report.passed = False

            
#         return report
"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13

This class checks if execution logging is enabled for all stages in API Gateway REST APIs.
It verifies that each stage has proper method settings with logging level set to either ERROR or INFO.
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError, BotoCoreError

class apigateway_execution_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Executes the check to verify if execution logging is enabled for API Gateway stages.
        
        Args:
            connection (boto3.Session): AWS session for making API calls
            
        Returns:
            CheckReport: Report containing the check results
            
        The check passes if all stages have execution logging enabled (ERROR or INFO level).
        The check fails if any stage has logging disabled or missing method settings.
        """
        client = connection.client('apigateway')
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            # Retrieve all API Gateway REST APIs
            apis = client.get_rest_apis()
            
            # If no APIs exist, return with passed status
            if not apis.get('items'):
                return report
            
            for api in apis.get('items', []):
                api_id = api['id']
                api_name = api.get('name', 'Unnamed API')
                
                try:
                    # Retrieve all stages for the current API
                    stages = client.get_stages(restApiId=api_id)
                    
                    # Process each stage in the API
                    for stage in stages.get('item', []):
                        stage_name = stage['stageName']
                        resource_id = f"{api_name}/{stage_name}"
                        
                        # Default status is False until proven otherwise
                        report.resource_ids_status[resource_id] = False
                        
                        # Check if method settings exist and are properly configured
                        if 'methodSettings' in stage and stage['methodSettings']:
                            # Empty method settings indicate no logging configuration
                            if not stage['methodSettings']:
                                report.passed = False
                                continue
                            
                            # Verify logging level in method settings
                            logging_enabled = False
                            for key, settings in stage['methodSettings'].items():
                                # Check if logging level is set to either ERROR or INFO
                                if settings.get('loggingLevel') in ['ERROR', 'INFO']:
                                    logging_enabled = True
                                    break
                            
                            # Update report based on logging status
                            if logging_enabled:
                                report.resource_ids_status[resource_id] = True
                            else:
                                report.passed = False
                        else:
                            # No method settings or logging configuration found
                            report.passed = False
                
                except ClientError as ce:
                    # Handle API-specific errors (e.g., stage not found, permissions)
                    report.passed = False
                    #report.error = f"Error accessing stages for API {api_name}: {str(ce)}"  To be uncommented post framework changes  
                    continue

        except ClientError as ce:
            # Handle AWS API errors (e.g., invalid credentials, permissions)
            report.passed = False
            #report.error = f"AWS API Error: {str(ce)}"   - C
        except BotoCoreError as be:
            # Handle AWS SDK errors (e.g., network issues, invalid endpoints)
            report.passed = False
            #report.error = f"AWS SDK Error: {str(be)}"
        except Exception as e:
            # Handle unexpected errors
            report.passed = False
            #report.error = f"Unexpected error occurred: {str(e)}"
            
        return report
