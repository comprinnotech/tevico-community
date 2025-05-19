import boto3
from datetime import datetime, timedelta, UTC
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource

def execute(self, connection=None):
    apigateway = boto3.client('apigateway')
    cloudwatch = boto3.client('cloudwatch')
    unused_stages = []

    apis = apigateway.get_rest_apis().get('items', [])

    for api in apis:
        api_id = api['id']
        api_name = api['name']
        stages = apigateway.get_stages(restApiId=api_id).get('item', [])

        for stage in stages:
            stage_name = stage['stageName']
            cache_enabled = stage.get('cacheClusterEnabled', False)

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

            request_counts = [point['Sum'] for point in metrics.get('Datapoints', [])]
            total_requests = sum(request_counts)

            if total_requests == 0:
                unused_stages.append(
                    AwsResource(
                        resource_id=api_id,
                        resource_name=api_name,
                        resource_type="ApiGateway",
                        status=CheckStatus.FAIL,
                        resource_data={
                            "stage_name": stage_name,
                            "cache_enabled": cache_enabled
                        }
                    )
                )

    status = CheckStatus.PASS if not unused_stages else CheckStatus.FAIL
    message = f"{len(unused_stages)} unused stages found." if unused_stages else "No unused stages found."

    report = CheckReport(
        status=status,
        message=message,
        resources=unused_stages
    )

    return report
