import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check
from datetime import datetime, timedelta, UTC

class CheckUnusedStages:
    def __init__(self, metadata):
        self.metadata = metadata

    def execute(self):
        apigateway = boto3.client('apigateway')
        cloudwatch = boto3.client('cloudwatch')
        unused_stages = []

        # Retrieve all REST APIs
        apis = apigateway.get_rest_apis().get('items', [])

        for api in apis:
            api_id = api['id']
            api_name = api['name']
            stages = apigateway.get_stages(restApiId=api_id).get('item', [])

            for stage in stages:
                stage_name = stage['stageName']
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

                request_counts = [point['Sum'] for point in metrics.get('Datapoints', [])]
                total_requests = sum(request_counts)

                if total_requests == 0:
                    unused_stages.append({
                        'api_id': api_id,
                        'api_name': api_name,
                        'stage_name': stage_name,
                        'cache_enabled': cache_enabled
                    })

        return {
            'status': 'PASS' if not unused_stages else 'FAIL',
            'unused_stages': unused_stages,
            'message': f"{len(unused_stages)} unused stages found." if unused_stages else "No unused stages found."
        }

# This exposes the class for Tevico to instantiate with metadata
apigateway_unused_stages = CheckUnusedStages
