# """
# AUTHOR: deepak-puri-comprinno
# EMAIL: deepak.puri@comprinno.net
# DATE: 2024-11-13
# """

# import boto3
# from tevico.engine.entities.report.check_model import CheckReport
# from tevico.engine.entities.check.check import Check

# class apigatewayv2_api_access_logging_enabled(Check):
#     def execute(self, connection: boto3.Session) -> CheckReport:
#         client = connection.client('apigatewayv2')
#         report = CheckReport(name=__name__)
#         report.passed = True
        
#         # List all API Gateway V2 APIs
#         apis = client.get_apis()
        
#         for api in apis.get('Items', []):
#             api_id = api['ApiId']
#             api_name = api.get('Name', 'Unnamed API')
            
#             # List all stages for the current API
#             stages = client.get_stages(ApiId=api_id)
            
#             # Assume check is passed unless a stage is missing logging
#             for stage in stages.get('Items', []):
#                 if 'AccessLogSettings' not in stage or not stage['AccessLogSettings'].get('DestinationArn'):
#                     # Logging is not enabled for this stage
#                     report.resource_ids_status[f"{api_name}/{stage['StageName']}"] = False
#                     report.passed = False
#                 else:
#                     # Logging is enabled for this stage
#                     report.resource_ids_status[f"{api_name}/{stage['StageName']}"] = True
            
#             # If any stage is missing logging, mark the API check as failed
        
#         return report
"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-09
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class apigatewayv2_api_access_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize API Gateway V2 client
        client = connection.client('apigatewayv2')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Initialize pagination for APIs
            apis = []
            next_token = None

            while True:
                if next_token:
                    response = client.get_apis(NextToken=next_token)
                else:
                    response = client.get_apis()

                apis.extend(response.get('Items', []))
                next_token = response.get('NextToken', None)

                if not next_token:
                    break

            # Check each API and its stages for access logging configuration
            for api in apis:
                api_id = api.get('ApiId')
                api_name = api.get('Name', 'Unnamed API')

                try:
                    # Fetch stages for the current API
                    stages = client.get_stages(ApiId=api_id).get('Items', [])

                    for stage in stages:
                        stage_name = stage.get('StageName')
                        resource_id = f"{api_name}/{stage_name}"

                        # Check if Access Log Settings are configured
                        access_log_settings = stage.get('AccessLogSettings', {})
                        destination_arn = access_log_settings.get('DestinationArn')

                        if destination_arn:
                            report.resource_ids_status[f"{resource_id} has access logging enabled."] = True
                        else:
                            report.resource_ids_status[f"{resource_id} has access logging disabled."] = False
                            report.passed = False

                except Exception as e:
                    report.resource_ids_status[f"Error fetching stages for {api_name}"] = False
                    report.passed = False

        except Exception as e:
            # Handle API listing errors
            report.resource_ids_status["API Gateway V2 listing error"] = False
            report.passed = False

        return report
