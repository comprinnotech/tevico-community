import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from library.aws.checks.iam.iam_attached_policy_admin_privileges_found import iam_attached_policy_admin_privileges_found
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata, Remediation, RemediationCode, RemediationRecommendation


class TestIamAttachedPolicyAdminPrivilegesFound:
    def setup_method(self):
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="iam_attached_policy_admin_privileges_found",
            CheckTitle="IAM Entities with Attached Admin Privileges",
            CheckType=["security"],
            ServiceName="iam",
            SubServiceName="attached-policies",
            ResourceIdTemplate="arn:aws:iam::{account_id}:{entity_type}/{entity_name}",
            Severity="high",
            ResourceType="iam-user/role/group",
            Risk="Admin or PowerUser privileges provide full access and can lead to privilege escalation or data exfiltration if misused.",
            RelatedUrl="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws iam detach-user-policy --user-name <username> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                    Terraform='resource "aws_iam_user_policy_attachment" "example" {\n  user       = "user_name"\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}',
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Avoid attaching 'AdministratorAccess' or 'PowerUserAccess' to IAM users, groups, or roles.",
                    Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
                )
            ),
            Description="Checks if any IAM user, group, or role has high-privilege policies like AdministratorAccess or PowerUserAccess attached.",
            Categories=["security", "iam"]
        )

        self.check = iam_attached_policy_admin_privileges_found(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

        # Simulate STS identity response
        self.mock_client.get_caller_identity.return_value = {"Account": "123456789012"}

    def test_user_with_admin_policy(self):
        self.mock_client.get_paginator.side_effect = lambda operation_name: {
            'list_users': MagicMock(paginate=lambda: [{'Users': [{'UserName': 'admin-user'}]}]),
            'list_attached_user_policies': MagicMock(paginate=lambda UserName: [{'AttachedPolicies': [{'PolicyName': 'AdministratorAccess'}]}]),
            'list_roles': MagicMock(paginate=lambda: [{'Roles': []}]),
            'list_groups': MagicMock(paginate=lambda: [{'Groups': []}])
        }[operation_name]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        failed = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]
        assert len(failed) == 1
        assert any(r.summary and "admin-user" in r.summary for r in failed)

    def test_user_without_admin_policy(self):
        self.mock_client.get_paginator.side_effect = lambda operation_name: {
            'list_users': MagicMock(paginate=lambda: [{'Users': [{'UserName': 'readonly-user'}]}]),
            'list_attached_user_policies': MagicMock(paginate=lambda UserName: [{'AttachedPolicies': [{'PolicyName': 'ReadOnlyAccess'}]}]),
            'list_roles': MagicMock(paginate=lambda: [{'Roles': []}]),
            'list_groups': MagicMock(paginate=lambda: [{'Groups': []}])
        }[operation_name]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        passed = [r for r in report.resource_ids_status if r.status == CheckStatus.PASSED]
        assert any(r.summary and "readonly-user" in r.summary for r in passed)

    def test_no_users_roles_groups(self):
        self.mock_client.get_paginator.side_effect = lambda operation_name: {
            'list_users': MagicMock(paginate=lambda: [{'Users': []}]),
            'list_roles': MagicMock(paginate=lambda: [{'Roles': []}]),
            'list_groups': MagicMock(paginate=lambda: [{'Groups': []}])
        }[operation_name]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.NOT_APPLICABLE
        assert any(r.summary and "No IAM users, roles, or groups" in r.summary for r in report.resource_ids_status)

    def test_sts_failure(self):
        self.mock_client.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "GetCallerIdentity"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        # Changed from FAILED to UNKNOWN in the check status filter here
        assert any(
            r.summary and "Failed to retrieve AWS account ID" in r.summary
            for r in report.resource_ids_status
            if r.status == CheckStatus.UNKNOWN
        )
