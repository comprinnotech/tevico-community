import boto3
from datetime import datetime, timedelta, UTC

def check_unused_stages():
    apigateway = boto3.client('apigateway')
    cloudwatch = boto3.client('cloudwatch')
    unused_stages = []

    # Retrieve all REST APIs
    apis = apigateway.get_rest_apis()['items']

    for api in apis:
        api_id = api['id']
        api_name = api['name']
        stages = apigateway.get_stages(restApiId=api_id)['item']

        for stage in stages:
            stage_name = stage['stageName']
            # Check if caching is enabled
            cache_enabled = stage.get('cacheClusterEnabled', False)

            # Retrieve CloudWatch metrics for the stage
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

            # Sum the request counts
            request_counts = [point['Sum'] for point in metrics.get('Datapoints', [])]
            total_requests = sum(request_counts)

            if total_requests == 0:
                unused_stages.append({
                    'api_id': api_id,
                    'api_name': api_name,
                    'stage_name': stage_name,
                    'cache_enabled': cache_enabled
                })

    return unused_stages
