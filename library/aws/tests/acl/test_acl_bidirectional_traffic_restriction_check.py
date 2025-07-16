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
from library.aws.checks.acl.acl_bidirectional_traffic_restriction_check import (
    acl_bidirectional_traffic_restriction_check,
)


class TestAclBidirectionalTrafficRestrictionCheck:
    """Test cases for ACL bidirectional traffic restriction check."""

    def setup_method(self):
        self.metadata = CheckMetadata(
            Provider="AWS",
            CheckID="acl_bidirectional_traffic_restriction_check",
            CheckTitle="Check ACL Bidirectional Traffic Restriction",
            CheckType=["Security"],
            ServiceName="EC2",
            SubServiceName="NACL",
            ResourceIdTemplate="arn:aws:ec2:{region}:{account}:network-acl/{acl_id}",
            Severity="medium",
            ResourceType="AWS::EC2::NetworkAcl",
            Risk="Overly permissive NACL rules can allow unwanted traffic.",
            Description="Checks for overly permissive bidirectional NACL rules.",
            Remediation=Remediation(
                Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
                Recommendation=RemediationRecommendation(
                    Text="Restrict NACL rules to only required traffic.",
                    Url="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
                ),
            ),
        )
        self.check = acl_bidirectional_traffic_restriction_check(metadata=self.metadata)
        self.mock_session = MagicMock()
        self.mock_ec2 = MagicMock()
        self.mock_sts = MagicMock()
        self.mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        self.mock_session.client.side_effect = lambda service: (
            self.mock_ec2 if service == "ec2" else self.mock_sts
        )

    def test_no_network_acls(self):
        self.mock_ec2.describe_network_acls.return_value = {"NetworkAcls": []}
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.NOT_APPLICABLE
        assert "No Network ACLs found" in report.resource_ids_status[0].summary

    def test_default_deny_rules(self):
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{"NetworkAclId": "acl-1", "Entries": []}]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert "default deny rules" in report.resource_ids_status[0].summary

    def test_permissive_ingress_egress(self):
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-2",
                "Entries": [
                    {"Egress": False, "RuleNumber": 100, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                    {"Egress": True, "RuleNumber": 100, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                ],
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "overly permissive rules in both ingress and egress" in report.resource_ids_status[0].summary

    def test_permissive_ingress_only(self):
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-3",
                "Entries": [
                    {"Egress": False, "RuleNumber": 100, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                    {"Egress": True, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                ],
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "overly permissive ingress rules" in report.resource_ids_status[0].summary

    def test_permissive_egress_only(self):
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-4",
                "Entries": [
                    {"Egress": False, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                    {"Egress": True, "RuleNumber": 100, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                ],
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "overly permissive egress rules" in report.resource_ids_status[0].summary

    def test_no_permissive_rules(self):
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-5",
                "Entries": [
                    {"Egress": False, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                    {"Egress": True, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                ],
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.PASSED
        assert "no overly permissive rules" in report.resource_ids_status[0].summary

    def test_client_error(self):
        self.mock_ec2.describe_network_acls.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "DescribeNetworkAcls"
        )
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "Error fetching Network ACLs" in report.resource_ids_status[0].summary
        assert report.resource_ids_status[0].exception is not None

    def test_mixed_rule_sets(self):
        """Test ACL with both secure and overly permissive entries."""
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-6",
                "Entries": [
                    {"Egress": False, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                    {"Egress": True, "RuleNumber": 200, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                ],
            }]
        }
        report = self.check.execute(self.mock_session)
        assert report.status == CheckStatus.FAILED
        assert "overly permissive egress rules" in report.resource_ids_status[0].summary
        assert report.resource_ids_status[0].resource.arn.endswith("acl-6")

    def test_multiple_acls_varying_results(self):
        """Test multiple ACLs with mixed compliance results."""
        self.mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-7",
                    "Entries": [
                        {"Egress": False, "RuleNumber": 100, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                        {"Egress": True, "RuleNumber": 100, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
                    ],
                },
                {
                    "NetworkAclId": "acl-8",
                    "Entries": [
                        {"Egress": False, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                        {"Egress": True, "RuleNumber": 100, "CidrBlock": "10.0.0.0/16", "RuleAction": "allow"},
                    ],
                },
            ]
        }
        report = self.check.execute(self.mock_session)
        assert len(report.resource_ids_status) == 2
        statuses = {r.status for r in report.resource_ids_status}
        assert CheckStatus.FAILED in statuses
        assert CheckStatus.PASSED in statuses
        assert report.status == CheckStatus.FAILED
