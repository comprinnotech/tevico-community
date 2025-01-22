"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigateway_rest_api_client_certificate_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize the API Gateway client
        client = connection.client('apigateway')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Initialize pagination for REST APIs
            apis = []
            next_token = None

            while True:
                response = client.get_rest_apis(position=next_token) if next_token else client.get_rest_apis()
                apis.extend(response.get('items', []))
                next_token = response.get('position', None)

                if not next_token:
                    break

            # Check each API and its stages for client certificate configuration
            for api in apis:
                api_id = api.get('id')
                api_name = api.get('name', 'Unnamed API')

                try:
                    # Fetch stages for the current API
                    stages_response = client.get_stages(restApiId=api_id)
                    stages = stages_response.get('item', [])

                    for stage in stages:
                        stage_name = stage.get('stageName', 'unknown')
                        resource_id = f"{api_name}/{stage_name}"

                        # Check if client certificate is enabled for this stage
                        has_cert = stage.get('clientCertificateId') is not None

                        if has_cert:
                            report.resource_ids_status[f"{resource_id} has a client certificate enabled."] = True
                        else:
                            report.resource_ids_status[f"{resource_id} does not have a client certificate enabled."] = False
                            report.status = ResourceStatus.FAILED

                except Exception as e:
                    report.resource_ids_status[f"Error fetching stages for {api_name}"] = False
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            # Handle API listing errors
            report.resource_ids_status["API Gateway listing error"] = False
            report.status = ResourceStatus.FAILED

        return report
