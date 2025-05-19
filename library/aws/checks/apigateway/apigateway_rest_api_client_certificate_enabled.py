"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigateway_rest_api_client_certificate_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize API Gateway client and check report
        client = connection.client("apigateway")
        region = connection.region_name
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Custom pagination for fetching REST APIs
            apis = []
            next_token = None

            while True:
                response =  client.get_rest_apis(position=next_token) if next_token else client.get_rest_apis()
                apis.extend(response.get("items", []))
                next_token = response.get("position")

                if not next_token:
                    break

            # Check each API and its stages for client certificate configuration
            for api in apis:
                api_id = api.get("id")
                api_name = api.get("name", "Unnamed API")

                try:
                    # Fetch stages for the current API
                    stages_response = client.get_stages(restApiId=api_id)
                    stages = stages_response.get("item", [])
                    resource_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"

                    for stage in stages:
                        stage_name = stage.get("stageName", "unknown")

                        # Check if client certificate is enabled
                        has_cert = stage.get("clientCertificateId") is not None

                        if has_cert:
                            summary = f"Stage {stage_name} of API {api_name} has a client certificate enabled."
                            status = CheckStatus.PASSED
                        else:
                            summary = f"Stage {stage_name} of API {api_name} does not have a client certificate enabled."
                            status = CheckStatus.FAILED
                            report.status = CheckStatus.FAILED

                        # Append result to report
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=resource_arn),
                                status=status,
                                summary=summary,
                            )
                        )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=f"arn:aws:apigateway:{region}::/restapis/{api_id}"),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error fetching stages for API {api_name}.",
                            exception=str(e),
                        )
                    )
                    report.status = CheckStatus.UNKNOWN

        except Exception as e:
            # Handle API listing errors
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="API Gateway listing error.",
                    exception=str(e)
                )
            )
            report.status = CheckStatus.UNKNOWN
        return report
