import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
from library.aws.checks.apigateway.apigateway_restapi_logging_enabled import apigateway_restapi_logging_enabled

class TestApiGatewayRestApiLoggingEnabled:
    """Test cases for API Gateway REST API Logging Enabled check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="apigateway_restapi_logging_enabled",
            CheckTitle="API Gateway REST API logging is enabled",
            CheckType=["Security"],
            ServiceName="APIGateway",
            SubServiceName="REST API",
            ResourceIdTemplate="arn:aws:apigateway:{region}::/restapis/{restapi_id}",
            Severity="medium",
            ResourceType="AWS::ApiGateway::RestApi",
            Risk="APIs without logging may not provide sufficient audit trails.",
            Description="Checks if API Gateway REST APIs have logging enabled.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Enable logging for API Gateway REST APIs.",
                    Url="https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html"
                )
            )
        )
        self.check = apigateway_restapi_logging_enabled(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_apigw = MagicMock()
        self.mock_session.client.return_value = self.mock_apigw

    @patch("boto3.Session.client")
    def test_no_rest_apis(self, mock_client):
        """Test when there are no REST APIs."""
        self.mock_apigw.get_rest_apis.return_value = {"items": []}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.SKIPPED
        assert report.resource_ids_status == []

    @patch("boto3.Session.client")
    def test_logging_enabled(self, mock_client):
        """Test when all REST APIs have logging enabled."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-1", "name": "API 1"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [{
                "stageName": "prod",
                "methodSettings": {
                    "*/*": {
                        "loggingLevel": "INFO"
                    }
                }
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert "Logging is enabled for stage prod of API API 1." == report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_logging_disabled(self, mock_client):
        """Test when a REST API does not have logging enabled."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-2", "name": "API 2"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [{
                "stageName": "prod",
                "methodSettings": {
                    "*/*": {
                        "loggingLevel": "OFF"
                    }
                }
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "Logging is disabled for stage prod of API API 2." == report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_client_error(self, mock_client):
        """Test error handling when a ClientError occurs."""
        self.mock_apigw.get_rest_apis.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetRestApis")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].summary