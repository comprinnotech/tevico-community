import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import (
    CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
)
from library.aws.checks.apigateway.apigateway_rest_api_client_certificate_enabled import apigateway_rest_api_client_certificate_enabled

class TestApiGatewayRestApiClientCertificateEnabled:
    """Test cases for API Gateway REST API Client Certificate Enabled check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="apigateway_rest_api_client_certificate_enabled",
            CheckTitle="API Gateway REST API requires client certificate",
            CheckType=["Security"],
            ServiceName="APIGateway",
            SubServiceName="REST API",
            ResourceIdTemplate="arn:aws:apigateway:{region}::/restapis/{restapi_id}",
            Severity="medium",
            ResourceType="AWS::ApiGateway::RestApi",
            Risk="APIs without client certificate may be accessed by unauthorized clients.",
            Description="Checks if API Gateway REST APIs require client certificates.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Enable client certificate requirement for API Gateway REST APIs.",
                    Url="https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-certificate.html"
                )
            )
        )
        self.check = apigateway_rest_api_client_certificate_enabled(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_apigw = MagicMock()
        self.mock_session.client.return_value = self.mock_apigw

    @patch("boto3.Session.client")
    def test_no_rest_apis(self, mock_client):
        """Test when there are no REST APIs."""
        self.mock_apigw.get_rest_apis.return_value = {"items": []}
        report = self.check.execute(self.mock_session)
        # The check returns PASSED when no APIs are found, not NOT_APPLICABLE
        assert report.status == CheckStatus.PASSED
        # The summary is likely in resource_ids_status, but if empty, just check that it's empty
        assert report.resource_ids_status == [] or all(
            "No API Gateway REST APIs found" in r.summary for r in report.resource_ids_status
        )

    @patch("boto3.Session.client")
    def test_client_certificate_enabled(self, mock_client):
        """Test when all REST APIs require client certificates."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-1", "name": "API 1"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [{"stageName": "prod", "clientCertificateId": "cert-123"}]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        # The summary says "has a client certificate enabled"
        assert "has a client certificate enabled" in report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_client_certificate_disabled(self, mock_client):
        """Test when a REST API does not require client certificates."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-2", "name": "API 2"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [{"stageName": "prod", "clientCertificateId": None}]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        # The summary says "does not have a client certificate enabled"
        assert "does not have a client certificate enabled" in report.resource_ids_status[0].summary

    @patch("boto3.Session.client")
    def test_client_error(self, mock_client):
        """Test error handling when a ClientError occurs."""
        self.mock_apigw.get_rest_apis.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetRestApis")
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].summary