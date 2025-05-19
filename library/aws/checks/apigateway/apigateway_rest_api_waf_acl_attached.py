"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigateway_rest_api_waf_acl_attached(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the API Gateway client and check report
        apigw_client = connection.client("apigateway")
        region = connection.region_name
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Fetch all REST APIs with pagination
            apis = []
            next_token = None

            while True:
                response = apigw_client.get_rest_apis(position=next_token) if next_token else apigw_client.get_rest_apis()
                apis.extend(response.get("items", []))
                next_token = response.get("position")

                if not next_token:
                    break

            # Check each API and its stages for WAF ACL attachment
            for api in apis:
                api_id = api["id"]
                api_name = api.get("name", "Unnamed API")
                api_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"

                try:
                    # Fetch stages for the current API
                    stages = apigw_client.get_stages(restApiId=api_id).get("item", [])

                    if not stages:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=api_arn),
                                status=CheckStatus.FAILED,
                                summary=f"API {api_name} has no stages."
                            )
                        )
                        report.status = CheckStatus.FAILED
                        continue

                    api_has_waf = False

                    for stage in stages:
                        stage_name = stage["stageName"]
                        resource_arn = api_arn
                        web_acl_id = stage.get("webAclArn")

                        if web_acl_id:
                            api_has_waf = True
                            summary = f"WAF is attached to stage {stage_name} of API {api_name}."
                            status = CheckStatus.PASSED
                        else:
                            summary = f"No WAF attached to stage {stage_name} of API {api_name}."
                            status = CheckStatus.FAILED
                            report.status = CheckStatus.FAILED

                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=resource_arn),
                                status=status,
                                summary=summary,
                            )
                        )

                    if not api_has_waf:
                        report.status = CheckStatus.FAILED

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
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="API Gateway listing error occurred.",
                    exception=str(e),
                )
            )
            report.status = CheckStatus.UNKNOWN
        return report
