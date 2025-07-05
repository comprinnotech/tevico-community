import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
from library.aws.checks.apigateway.apigateway_rest_api_waf_acl_attached import apigateway_rest_api_waf_acl_attached


class TestApiGatewayRestApiWafAclAttached:
    """Tests for apigateway_rest_api_waf_acl_attached check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="apigateway_rest_api_waf_acl_attached",
            CheckTitle="API Gateway REST API has WAF ACL attached",
            CheckType=["Security"],
            ServiceName="APIGateway",
            SubServiceName="REST API",
            ResourceIdTemplate="arn:aws:apigateway:{region}::/restapis/{restapi_id}",
            Severity="medium",
            ResourceType="AWS::ApiGateway::RestApi",
            Risk="APIs without WAF ACL may be vulnerable to web attacks.",
            Description="Checks if API Gateway REST APIs have a WAF ACL attached.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Attach a WAF ACL to API Gateway REST APIs.",
                    Url="https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html"
                )
            )
        )
        self.check = apigateway_rest_api_waf_acl_attached(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_apigw = MagicMock()
        self.mock_session.client.return_value = self.mock_apigw

    def test_all_rest_apis_have_waf_acl(self):
        """PASSED when all REST API stages have WAF ACL attached."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-1", "name": "API 1"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [
                {"stageName": "prod", "tags": {"aws:apigateway:rest-api-waf-acl": "waf-123"}}
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED, f"Expected PASSED, got {report.status}"
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "WAF is attached to stage prod of API API 1." in report.resource_ids_status[0].summary

    def test_rest_api_without_waf_acl(self):
        """FAILED when REST API stage has no WAF ACL attached."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-2", "name": "API 2"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": [
                {"stageName": "prod", "tags": {}}
            ]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "No WAF attached to stage prod of API API 2." in report.resource_ids_status[0].summary

    def test_rest_api_with_no_stages(self):
        """FAILED when REST API has no stages."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-3", "name": "API 3"}]
        }
        self.mock_apigw.get_stages.return_value = {
            "item": []
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "API API 3 has no stages." in report.resource_ids_status[0].summary

    def test_client_error_on_get_stages(self):
        """UNKNOWN when get_stages raises a ClientError."""
        self.mock_apigw.get_rest_apis.return_value = {
            "items": [{"id": "api-4", "name": "API 4"}]
        }
        self.mock_apigw.get_stages.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "GetStages"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error fetching stages for API API 4." in report.resource_ids_status[0].summary

    def test_client_error_on_get_rest_apis(self):
        """UNKNOWN when get_rest_apis raises a ClientError."""
        self.mock_apigw.get_rest_apis.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "GetRestApis"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "API Gateway listing error occurred." in report.resource_ids_status[0].summary

    def test_no_rest_apis(self):
        """PASSED when no REST APIs are present."""
        self.mock_apigw.get_rest_apis.return_value = {"items": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status == []
