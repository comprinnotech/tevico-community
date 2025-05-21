"""
AUTHOR: gunjan-katre-comprinno
EMAIL: gunjan.katre@comprinno.net
DATE: 2025-05-19+

+

"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, ResourceStatus
from tevico.engine.entities.check.check import Check
from datetime import datetime, timedelta, UTC

class apigateway_unused_stages(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("apigateway")
        cloudwatch = connection.client("cloudwatch")
        region = connection.region_name

        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        unused_stages_found = False

        try:
            apis = []
            next_token = None
            # Paginate through all REST APIs
            while True:
                if next_token:
                    response = client.get_rest_apis(position=next_token)
                else:
                    response = client.get_rest_apis()

                apis.extend(response.get("items", []))
                next_token = response.get("position")
                if not next_token:
                    break

            for api in apis:
                api_id = api.get("id")
                api_name = api.get("name", "Unnamed API")
                resource_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"

                try:
                    stages = client.get_stages(restApiId=api_id).get("item", [])

                    if not stages:
                        # No stages found for this API - mark as skipped
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=resource_arn),
                                status=CheckStatus.SKIPPED,
                                summary=f"API {api_name} has no stages.",
                            )
                        )
                        continue

                    for stage in stages:
                        stage_name = stage.get("stageName")
                        cache_enabled = stage.get("cacheClusterEnabled", False)

                        # Fetch CloudWatch metrics to see if stage has any requests
                        metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/ApiGateway',
                            MetricName='Count',
                            Dimensions=[
                                {'Name': 'ApiName', 'Value': api_name},
                                {'Name': 'Stage', 'Value': stage_name}
                            ],
                            StartTime=datetime.now(UTC) - timedelta(days=30),
                            EndTime=datetime.now(UTC),
                            Period=86400,
                            Statistics=['Sum']
                        )

                        datapoints = metrics.get("Datapoints", [])
                        total_requests = sum(point.get('Sum', 0) for point in datapoints)

                        if total_requests == 0:
                            unused_stages_found = True
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=resource_arn),
                                    status=CheckStatus.FAILED,
                                    summary=f"Stage '{stage_name}' of API '{api_name}' is unused (0 requests in last 30 days). Cache enabled: {cache_enabled}"
                                )
                            )
                        else:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=resource_arn),
                                    status=CheckStatus.PASSED,
                                    summary=f"Stage '{stage_name}' of API '{api_name}' has usage (total {total_requests} requests in last 30 days)."
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

            if unused_stages_found:
                report.status = CheckStatus.FAILED
            else:
                report.status = CheckStatus.PASSED

        except Exception as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=AwsResource(arn=f"arn:aws:apigateway:{region}::/restapis"),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error listing API Gateway REST APIs: {str(e)}",
                    exception=str(e)
                )
            )
            report.status = CheckStatus.UNKNOWN

        return report