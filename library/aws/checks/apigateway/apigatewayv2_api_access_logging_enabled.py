"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-09
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigatewayv2_api_access_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize API Gateway V2 client and check report
        client = connection.client("apigatewayv2")
        region = connection.region_name
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Custom pagination for fetching APIs
            apis = []
            next_token = None

            while True:
                response = client.get_apis(NextToken=next_token) if next_token else client.get_apis()
                apis.extend(response.get("Items", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # Check each API and its stages for access logging configuration
            for api in apis:
                api_id = api.get("ApiId")
                api_name = api.get("Name", "Unnamed API")
                api_arn = f"arn:aws:apigateway:{region}::/apis/{api_id}"

                try:
                    # Fetch stages for the current API
                    stages = client.get_stages(ApiId=api_id).get("Items", [])

                    if not stages:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=api_arn),
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"API {api_name} has no stages.",
                            )
                        )
                        report.status = CheckStatus.NOT_APPLICABLE
                        continue

                    for stage in stages:
                        stage_name = stage.get("StageName", "unknown")
                        access_log_settings = stage.get("AccessLogSettings", {})
                        destination_arn = access_log_settings.get("DestinationArn")

                        if destination_arn:
                            summary = f"Access logging is enabled for stage {stage_name} of API {api_name}."
                            status = CheckStatus.PASSED
                        else:
                            summary = f"Access logging is disabled for stage {stage_name} of API {api_name}."
                            status = CheckStatus.FAILED
                            report.status = CheckStatus.FAILED

                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=api_arn),
                                status=status,
                                summary=summary,
                            )
                        )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=api_arn),
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
                    summary=f"API Gateway V2 listing error: {str(e)}",
                    exception=str(e)
                )
            )
            report.status = CheckStatus.UNKNOWN
        return report
