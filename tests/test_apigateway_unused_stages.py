import unittest
from unittest.mock import patch, MagicMock
from library.aws.checks.apigateway.apigateway_unused_stages import check_unused_stages

class TestApiGatewayUnusedStages(unittest.TestCase):

    @patch("library.aws.checks.apigateway.apigateway_unused_stages.boto3.client")
    def test_detects_single_unused_stage(self, mock_boto_client):
        mock_apigateway = MagicMock()
        mock_cloudwatch = MagicMock()

        def client_side_effect(service_name):
            return mock_apigateway if service_name == "apigateway" else mock_cloudwatch
        mock_boto_client.side_effect = client_side_effect

        mock_apigateway.get_rest_apis.return_value = {
            'items': [{'id': 'api123', 'name': 'UsedAPI'}, {'id': 'api456', 'name': 'UnusedAPI'}]
        }

        def get_stages_side_effect(restApiId):
            return {'item': [{'stageName': 'prod', 'cacheClusterEnabled': False}]} if restApiId == 'api123' \
                else {'item': [{'stageName': 'dev', 'cacheClusterEnabled': True}]}
        mock_apigateway.get_stages.side_effect = get_stages_side_effect

        def metric_stats_side_effect(Namespace, MetricName, Dimensions, StartTime, EndTime, Period, Statistics):
            return {'Datapoints': [{'Sum': 15.0}]} if Dimensions[0]['Value'] == 'UsedAPI' else {'Datapoints': []}
        mock_cloudwatch.get_metric_statistics.side_effect = metric_stats_side_effect

        result = check_unused_stages()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['api_id'], 'api456')
        self.assertEqual(result[0]['stage_name'], 'dev')

    @patch("library.aws.checks.apigateway.apigateway_unused_stages.boto3.client")
    def test_no_apis_exist(self, mock_boto_client):
        mock_apigateway = MagicMock()
        mock_cloudwatch = MagicMock()
        mock_boto_client.side_effect = lambda s: mock_apigateway if s == "apigateway" else mock_cloudwatch

        mock_apigateway.get_rest_apis.return_value = {'items': []}

        result = check_unused_stages()
        self.assertEqual(result, [])

    @patch("library.aws.checks.apigateway.apigateway_unused_stages.boto3.client")
    def test_api_with_no_stages(self, mock_boto_client):
        mock_apigateway = MagicMock()
        mock_cloudwatch = MagicMock()
        mock_boto_client.side_effect = lambda s: mock_apigateway if s == "apigateway" else mock_cloudwatch

        mock_apigateway.get_rest_apis.return_value = {
            'items': [{'id': 'api123', 'name': 'LonelyAPI'}]
        }
        mock_apigateway.get_stages.return_value = {'item': []}

        result = check_unused_stages()
        self.assertEqual(result, [])

    @patch("library.aws.checks.apigateway.apigateway_unused_stages.boto3.client")
    def test_missing_metrics(self, mock_boto_client):
        mock_apigateway = MagicMock()
        mock_cloudwatch = MagicMock()
        mock_boto_client.side_effect = lambda s: mock_apigateway if s == "apigateway" else mock_cloudwatch

        mock_apigateway.get_rest_apis.return_value = {
            'items': [{'id': 'api789', 'name': 'BrokenAPI'}]
        }
        mock_apigateway.get_stages.return_value = {
            'item': [{'stageName': 'qa', 'cacheClusterEnabled': False}]
        }
        mock_cloudwatch.get_metric_statistics.return_value = {}  # Malformed/no 'Datapoints'

        result = check_unused_stages()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['api_id'], 'api789')
        self.assertEqual(result[0]['stage_name'], 'qa')

    @patch("library.aws.checks.apigateway.apigateway_unused_stages.boto3.client")
    def test_multiple_unused_stages(self, mock_boto_client):
        mock_apigateway = MagicMock()
        mock_cloudwatch = MagicMock()
        mock_boto_client.side_effect = lambda s: mock_apigateway if s == "apigateway" else mock_cloudwatch

        mock_apigateway.get_rest_apis.return_value = {
            'items': [
                {'id': 'api111', 'name': 'API1'},
                {'id': 'api222', 'name': 'API2'}
            ]
        }

        def get_stages_side_effect(restApiId):
            return {'item': [{'stageName': 'alpha', 'cacheClusterEnabled': False}]} if restApiId == 'api111' \
                else {'item': [{'stageName': 'beta', 'cacheClusterEnabled': False}]}
        mock_apigateway.get_stages.side_effect = get_stages_side_effect

        mock_cloudwatch.get_metric_statistics.return_value = {'Datapoints': []}

        result = check_unused_stages()
        self.assertEqual(len(result), 2)
        self.assertEqual({r['stage_name'] for r in result}, {'alpha', 'beta'})

if __name__ == "__main__":
    unittest.main()
