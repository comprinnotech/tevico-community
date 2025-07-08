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
from library.aws.checks.networkfirewall.networkfirewall_logging_enabled import networkfirewall_logging_enabled


class TestNetworkFirewallLoggingEnabled:

    def setup_method(self):
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="networkfirewall_logging_enabled",
            CheckTitle="Ensure Network Firewall logging is enabled",
            CheckType=["security"],
            ServiceName="network-firewall",
            SubServiceName="logging",
            ResourceIdTemplate="arn:aws:network-firewall:{region}:{account}:firewall/{firewall_name}",
            Severity="high",
            ResourceType="AWS::NetworkFirewall::Firewall",
            Risk="Without logging, traffic going through Network Firewall cannot be monitored or audited.",
            RelatedUrl="https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws network-firewall update-logging-configuration --firewall-arn <value> --logging-configuration file://logging.json"
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable logging for all Network Firewall resources.",
                    Url="https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging.html"
                ),
            ),
            Description="Checks whether logging is enabled for AWS Network Firewall.",
            Categories=["security", "audit"]
        )
        self.check = networkfirewall_logging_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_no_firewalls(self):
        self.mock_client.list_firewalls.return_value = {"Firewalls": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE
        assert report.resource_ids_status[0].summary == "No Network Firewall resources found."

    def test_firewall_with_logging_enabled(self):
        self.mock_client.list_firewalls.return_value = {
            "Firewalls": [{
                "FirewallName": "fw-enabled",
                "FirewallArn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw-enabled"
            }]
        }
        self.mock_client.describe_logging_configuration.return_value = {
            "LoggingConfiguration": {
                "LogDestinationConfigs": [{"LogType": "ALERT", "LogDestinationType": "CloudWatchLogs"}]
            }
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert report.resource_ids_status[0].summary == "Logging is enabled for Network Firewall fw-enabled."

    def test_firewall_with_logging_disabled(self):
        self.mock_client.list_firewalls.return_value = {
            "Firewalls": [{
                "FirewallName": "fw-disabled",
                "FirewallArn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw-disabled"
            }]
        }
        self.mock_client.describe_logging_configuration.return_value = {
            "LoggingConfiguration": {
                "LogDestinationConfigs": []
            }
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert report.resource_ids_status[0].summary == "Logging is not enabled for Network Firewall fw-disabled."

    def test_firewall_logging_config_error(self):
        self.mock_client.list_firewalls.return_value = {
            "Firewalls": [{
                "FirewallName": "fw-error",
                "FirewallArn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw-error"
            }]
        }
        self.mock_client.describe_logging_configuration.side_effect = Exception("Describe error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].summary is not None
        assert "Error retrieving logging configuration for fw-error." in report.resource_ids_status[0].summary

    def test_list_firewalls_raises_exception(self):
        self.mock_client.list_firewalls.side_effect = Exception("List error")

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving firewall list" in report.resource_ids_status[0].summary

    def test_list_firewalls_client_error(self):
        self.mock_client.list_firewalls.side_effect = ClientError(
            error_response={"Error": {"Code": "AccessDeniedException", "Message": "You don't have permission"}},
            operation_name="ListFirewalls"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error retrieving firewall list" in report.resource_ids_status[0].summary
        assert "accessdenied" in report.resource_ids_status[0].summary.lower()

    def test_paginated_firewall_list(self):
        # Simulate two pages of results
        self.mock_client.list_firewalls.side_effect = [
            {"Firewalls": [
                {"FirewallName": "fw1", "FirewallArn": "arn:aws:network-firewall:region:acct:firewall/fw1"}
            ], "NextToken": "page2"},
            {"Firewalls": [
                {"FirewallName": "fw2", "FirewallArn": "arn:aws:network-firewall:region:acct:firewall/fw2"}
            ]}
        ]

        self.mock_client.describe_logging_configuration.side_effect = [
            {"LoggingConfiguration": {"LogDestinationConfigs": []}},  # fw1 - disabled
            {"LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": "FLOW"}]}}  # fw2 - enabled
        ]

        report = self.check.execute(self.mock_session)

        # One firewall failed, one passed → overall FAILED
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 2
        summaries = [r.summary for r in report.resource_ids_status]
        assert any("fw1" in s and "not enabled" in s for s in summaries)
        assert any("fw2" in s and "enabled" in s for s in summaries)
