"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class apigateway_restapi_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize API Gateway client
        client = connection.client('apigateway')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Initialize pagination for REST APIs
            apis = []
            next_position = None

            while True:
                if next_position:
                    response = client.get_rest_apis(position=next_position)
                else:
                    response = client.get_rest_apis()

                apis.extend(response.get('items', []))
                next_position = response.get('position', None)

                if not next_position:
                    break

            # Check each API and its stages for logging configuration
            for api in apis:
                api_id = api.get('id')
                api_name = api.get('name', 'Unnamed API')

                try:
                    # Fetch stages for the current API
                    stages = client.get_stages(restApiId=api_id).get('item', [])

                    for stage in stages:
                        stage_name = stage.get('stageName')
                        resource_id = f"{api_name}/{stage_name}"

                        # Check method settings for logging
                        method_settings = stage.get('methodSettings', {})
                        default_method = method_settings.get('*/*', {})
                        logging_level = default_method.get('loggingLevel')

                        # Determine logging status
                        if logging_level in ['ERROR', 'INFO']:
                            report.resource_ids_status[f"{resource_id} has logging enabled"] = True
                        else:
                            report.resource_ids_status[f"{resource_id} has logging disabled"] = False
                            report.passed = False

                except Exception as e:
                    report.resource_ids_status[f"Error fetching stages for {api_name}"] = False
                    report.passed = False

        except Exception as e:
            # Handle API listing errors
            report.resource_ids_status["API Gateway listing error"] = False
            report.passed = False

        return report

