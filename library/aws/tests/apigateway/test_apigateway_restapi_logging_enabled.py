import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.apigateway.apigateway_restapi_logging_enabled import (
    apigateway_restapi_logging_enabled,
)


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
        self.mock_session.region_name = "ap-south-1"

    def test_no_rest_apis(self):
        """Should SKIP when there are no REST APIs."""
        self.mock_apigw.get_rest_apis.return_value = {"items": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.SKIPPED
        assert report.resource_ids_status == []

    def test_api_with_no_stages(self):
        """Should SKIP individual APIs that have no stages."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-1", "name": "API 1"}]
        }
        self.mock_apigw.get_stages.return_value = {"item": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.SKIPPED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.SKIPPED
        assert "API API 1 has no stages." in report.resource_ids_status[0].summary

    def test_logging_enabled(self):
        """Should pass when API has logging enabled."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-1", "name": "API 1"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [
                {
                    "stageName": "prod",
                    "methodSettings": {"*/*": {"loggingLevel": "INFO"}}
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "Logging is enabled for stage prod of API API 1." in report.resource_ids_status[0].summary

    def test_logging_disabled(self):
        """Should fail when logging is disabled or missing."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-2", "name": "API 2"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [
                {
                    "stageName": "test",
                    "methodSettings": {"*/*": {"loggingLevel": "OFF"}}
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Logging is disabled for stage test of API API 2." in report.resource_ids_status[0].summary

    def test_logging_key_missing(self):
        """Should fail if loggingLevel key is missing (treat as disabled)."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-3", "name": "API 3"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [
                {
                    "stageName": "dev",
                    "methodSettings": {"*/*": {}}  # No loggingLevel
                }
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "Logging is disabled for stage dev of API API 3." in report.resource_ids_status[0].summary

    def test_stage_fetch_exception(self):
        """Should mark UNKNOWN if exception occurs during stage fetch."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-4", "name": "API 4"}]
        }
        self.mock_apigw.get_stages.side_effect = Exception("Something went wrong")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error fetching stages for API API 4" in report.resource_ids_status[0].summary

    def test_get_rest_apis_error(self):
        """Should mark UNKNOWN if get_rest_apis fails."""
        self.mock_apigw.get_rest_apis.side_effect = Exception("Connection refused")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "API Gateway listing error" in report.resource_ids_status[0].summary
