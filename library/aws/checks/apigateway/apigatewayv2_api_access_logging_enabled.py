
"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-09
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigatewayv2_api_access_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize API Gateway V2 client
        client = connection.client('apigatewayv2')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
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

                    if not stages:
                        # If no stages are present, set resource_ids_status to False
                        report.resource_ids_status[f"{api_name} has no stages."] = False
                        report.status = ResourceStatus.FAILED
                        continue

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
                            report.status = ResourceStatus.FAILED

                except Exception as e:
                    report.resource_ids_status[f"Error fetching stages for {api_name}"] = False
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            # Handle API listing errors
            report.resource_ids_status["API Gateway V2 listing error"] = False
            report.status = ResourceStatus.FAILED

        return report
