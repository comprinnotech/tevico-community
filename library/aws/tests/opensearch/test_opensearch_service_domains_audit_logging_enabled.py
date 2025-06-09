"""
Test for OpenSearch domains audit logging enabled check.
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.opensearch.opensearch_service_domains_audit_logging_enabled import opensearch_service_domains_audit_logging_enabled
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, AwsResource, GeneralResource
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestOpenSearchServiceDomainsAuditLoggingEnabled:
    """Test cases for OpenSearch domains audit logging enabled check."""

    def setup_method(self):
        """Set up test method."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="opensearch_service_domains_audit_logging_enabled",
            CheckTitle="Ensure OpenSearch domains have audit logging enabled",
            CheckType=["security"],
            ServiceName="opensearch",
            SubServiceName="domains",
            ResourceIdTemplate="arn:aws:es::{account_id}:domain/{domain_name}",
            Severity="high",
            ResourceType="opensearch-domain",
            Risk="Audit logs provide traceability and accountability",
            RelatedUrl="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws opensearch update-domain-config --domain-name <domain> --log-publishing-options '{\"AUDIT_LOGS\":{\"Enabled\":true}}'",
                    Terraform='resource "aws_opensearch_domain" "example" {\n  domain_name = "<domain>"\n  log_publishing_options {\n    audit_logs {\n      enabled = true\n    }\n  }\n}',
                    NativeIaC=None,
                    Other=None,
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable audit logging on your OpenSearch domains for security auditing.",
                    Url="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html",
                ),
            ),
            Description="Checks if OpenSearch domains have audit logging enabled",
            Categories=["security", "compliance"]
        )
        self.check = opensearch_service_domains_audit_logging_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_no_domains_found(self):
        """Test case when no OpenSearch domains exist."""
        self.mock_client.list_domain_names.return_value = {"DomainNames": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].summary == "No OpenSearch domains found."

    def test_domain_with_audit_logging_enabled(self):
        """Test domain with audit logging enabled."""
        self.mock_client.list_domain_names.return_value = {"DomainNames": [{"DomainName": "domain1"}]}
        self.mock_client.describe_domain.return_value = {
            "DomainStatus": {
                "ARN": "arn:aws:es:region:account-id:domain/domain1",
                "LogPublishingOptions": {
                    "AUDIT_LOGS": {"Enabled": True}
                }
            }
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        res_status = report.resource_ids_status[0]
        assert res_status.status == CheckStatus.PASSED
        assert "Audit logging enabled" in (res_status.summary or "")

    def test_domain_with_audit_logging_disabled(self):
        """Test domain with audit logging disabled."""
        self.mock_client.list_domain_names.return_value = {"DomainNames": [{"DomainName": "domain1"}]}
        self.mock_client.describe_domain.return_value = {
            "DomainStatus": {
                "ARN": "arn:aws:es:region:account-id:domain/domain1",
                "LogPublishingOptions": {
                    "AUDIT_LOGS": {"Enabled": False}
                }
            }
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        res_status = report.resource_ids_status[0]
        assert res_status.status == CheckStatus.FAILED
        assert "Audit logging not enabled" in (res_status.summary or "")

    def test_error_during_list_domains(self):
        """Test error when listing domains."""
        self.mock_client.list_domain_names.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "ListDomainNames"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        res_status = report.resource_ids_status[0]
        assert res_status.status == CheckStatus.UNKNOWN
        assert "Error retrieving OpenSearch domains" in (res_status.summary or "")

    def test_error_during_describe_domain(self):
        """Test error when describing domain."""
        self.mock_client.list_domain_names.return_value = {"DomainNames": [{"DomainName": "domain1"}]}
        self.mock_client.describe_domain.side_effect = Exception("Some error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        res_status = report.resource_ids_status[0]
        assert res_status.status == CheckStatus.UNKNOWN
        assert "Error retrieving audit logging status" in (res_status.summary or "")
