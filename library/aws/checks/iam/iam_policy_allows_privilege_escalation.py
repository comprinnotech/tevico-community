"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:UpdateLoginProfile",
    "iam:ResetServiceSpecificCredential",
    "iam:CreateServiceLinkedRole",
    "iam:UpdateUser",
    "iam:UpdateRole",
    "iam:UpdateGroup",
    "iam:PutRolePermissionsBoundary",
    "iam:PutUserPermissionsBoundary",
    "iam:PutGroupPermissionsBoundary",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteGroupPermissionsBoundary",
    "iam:DeletePolicyVersion",
    "iam:DeletePolicy",
    "iam:CreateInstanceProfile",
    "iam:AddRoleToInstanceProfile",
    "iam:UpdateInstanceProfile",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:DeleteInstanceProfile"
}

class iam_policy_allows_privilege_escalation(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        policies_found = False

        try:
            paginator = client.get_paginator("list_policies")
            policies_iterator = paginator.paginate(Scope="Local")

            for page in policies_iterator:
                for policy in page.get("Policies", []):
                    policies_found = True
                    policy_arn = policy.get("Arn")
                    policy_name = policy.get("PolicyName")
                    
                    try:
                        policy_version = client.get_policy_version(
                            PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
                        )
                        statements = policy_version["PolicyVersion"]["Document"].get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]  # Ensure it's a list
                    except (BotoCoreError, ClientError) as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=policy_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Failed to retrieve policy version for {policy_name}",
                                exception=str(e)
                            )
                        )
                        continue
                    
                    privilege_escalation_found = False
                    for statement in statements:
                        if statement.get("Effect") == "Allow":
                            actions = statement.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]  # Ensure it's a list
                            
                            if any(action in PRIVILEGE_ESCALATION_ACTIONS for action in actions):
                                privilege_escalation_found = True
                                break
                    
                    if privilege_escalation_found:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=policy_arn),
                                status=CheckStatus.FAILED,
                                summary=f"Policy '{policy_name}' allows privilege escalation actions."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=policy_arn),
                                status=CheckStatus.PASSED,
                                summary=f"Policy '{policy_name}' does not allow privilege escalation actions."
                            )
                        )
            
            if not policies_found:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No IAM policies found in the account."
                    )
                )
                return report
        
        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve IAM policies.",
                    exception=str(e)
                )
            )
        
        return report