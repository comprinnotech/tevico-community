"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigateway_restapi_logging_enabled(Check):

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
                response = client.get_rest_apis(position=next_token) if next_token else client.get_rest_apis()
                apis.extend(response.get("items", []))
                next_token = response.get("position")

                if not next_token:
                    break

            #Flag to track if any API Gateway has stages
            has_stages = False

            # Check each API and its stages for logging configuration
            for api in apis:
                api_id = api.get("id")
                api_name = api.get("name", "Unnamed API")
                resource_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"

                try:
                    # Fetch stages for the current API
                    stages = client.get_stages(restApiId=api_id).get("item", [])
                    
                    if not stages:
                        # If no stages are present, mark as failed
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=resource_arn),
                                status=CheckStatus.SKIPPED,
                                summary=f"API {api_name} has no stages.",
                            )
                        )
                        continue

                    has_stages = True

                    for stage in stages:
                        stage_name = stage.get("stageName")

                        # Check method settings for logging
                        method_settings = stage.get("methodSettings", {})
                        default_method = method_settings.get("*/*", {})
                        logging_level = default_method.get("loggingLevel")

                        # Determine logging status
                        if logging_level in ["ERROR", "INFO"]:
                            summary = f"Logging is enabled for stage {stage_name} of API {api_name}."
                            status = CheckStatus.PASSED
                        else:
                            summary = f"Logging is disabled for stage {stage_name} of API {api_name}."
                            status = CheckStatus.FAILED
                            report.status = CheckStatus.FAILED

                        # Append result to report
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=resource_arn),
                                status=status,
                                summary=summary
                            )
                        )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=resource_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error fetching stages for API {api_name}: {str(e)}",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN
            
            # If no stages are present in any API, mark as skipped
            if not has_stages:
                report.status = CheckStatus.SKIPPED

        except Exception as e:
            # Handle API listing errors
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"API Gateway listing error: {str(e)}",
                    exception=str(e),
                )
            )
            report.status = CheckStatus.UNKNOWN
        return report
