"""
Test for EC2 Network ACL allowing ingress on any port.
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.ec2.ec2_network_acl_allow_ingress_any_port import ec2_network_acl_allow_ingress_any_port
from tevico.engine.entities.report.check_model import (
    CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation
)


class TestEc2NetworkAclAllowIngressAnyPort:
    """Test cases for EC2 NACL ingress all port allowance check."""

    def setup_method(self):
        """Set up test method with check metadata and mocks."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="ec2_network_acl_allow_ingress_any_port",
            CheckTitle="EC2 Network ACLs Should Not Allow Ingress on All Ports",
            CheckType=["security"],
            ServiceName="ec2",
            SubServiceName="nacl",
            ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:network-acl/{resource_id}",
            Severity="high",
            ResourceType="ec2-nacl",
            Risk="Allowing ingress from all ports opens the network to potential external attacks.",
            RelatedUrl="https://docs.aws.amazon.com/vpc/latest/userguide/network-acls.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws ec2 replace-network-acl-entry --network-acl-id acl-12345678 --rule-number 100 --protocol tcp --rule-action deny --egress --cidr-block 0.0.0.0/0 --port-range From=0,To=65535",
                    Terraform=None,
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Restrict NACL ingress rules to specific ports and CIDRs.",
                    Url="https://docs.aws.amazon.com/vpc/latest/userguide/network-acls.html"
                )
            ),
            Description="Ensure NACLs do not allow ingress on all ports (0-65535) from 0.0.0.0/0.",
            Categories=["security", "networking"]
        )

        self.check = ec2_network_acl_allow_ingress_any_port(metadata)
        self.mock_session = MagicMock()
        self.mock_ec2_client = MagicMock()
        self.mock_sts_client = MagicMock()

        self.mock_session.client.side_effect = lambda service: {
            "ec2": self.mock_ec2_client,
            "sts": self.mock_sts_client
        }[service]

        self.mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        self.mock_session.region_name = "us-east-1"

    def test_no_nacls_present(self):
        """Test when there are no NACLs in the account."""
        self.mock_ec2_client.describe_network_acls.return_value = {"NetworkAcls": []}

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert "No Network ACLs found in the account." in (report.resource_ids_status[0].summary or "")

    def test_nacl_allows_all_ports(self):
        """Test when a NACL allows ingress from 0.0.0.0/0 on all ports."""
        self.mock_ec2_client.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-1234abcd",
                "Entries": [
                    {
                        "Egress": False,
                        "RuleAction": "allow",
                        "CidrBlock": "0.0.0.0/0",
                        "PortRange": {"From": 0, "To": 65535},
                        "Protocol": "6"
                    }
                ]
            }]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "allows ingress on all ports from 0.0.0.0/0" in (report.resource_ids_status[0].summary or "")

    def test_nacl_blocks_all_ports(self):
        """Test when a NACL has no offending ingress rules."""
        self.mock_ec2_client.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-5678efgh",
                "Entries": [
                    {
                        "Egress": False,
                        "RuleAction": "allow",
                        "CidrBlock": "192.168.0.0/16",
                        "PortRange": {"From": 80, "To": 80},
                        "Protocol": "6"
                    }
                ]
            }]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "does not allow ingress on all ports" in (report.resource_ids_status[0].summary or "")

    def test_nacl_with_all_protocols(self):
        """Test when NACL rule uses Protocol -1 (all protocols)."""
        self.mock_ec2_client.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-9101ijkl",
                "Entries": [
                    {
                        "Egress": False,
                        "RuleAction": "allow",
                        "CidrBlock": "0.0.0.0/0",
                        "Protocol": "-1"
                    }
                ]
            }]
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "allows ingress on all ports from 0.0.0.0/0" in (report.resource_ids_status[0].summary or "")

    def test_client_error(self):
        """Test handling of boto3 client exception."""
        self.mock_ec2_client.describe_network_acls.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}}, "DescribeNetworkAcls"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error fetching Network ACLs" in (report.resource_ids_status[0].summary or "")
