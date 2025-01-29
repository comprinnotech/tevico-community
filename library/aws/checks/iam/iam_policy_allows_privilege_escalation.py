import boto3
import logging
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_policy_allows_privilege_escalation(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize the report status
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Privilege escalation patterns
        privilege_escalation_policies_combination = {
            "OverPermissiveIAM": frozenset({"iam:*"}),
            "IAMPut": frozenset({"iam:Put*"}),
            "CreatePolicyVersion": frozenset({"iam:CreatePolicyVersion"}),
            "SetDefaultPolicyVersion": frozenset({"iam:SetDefaultPolicyVersion"}),
            "iam:PassRole": frozenset({"iam:PassRole"}),
            "PassRole+EC2": frozenset({"iam:PassRole", "ec2:RunInstances"}),
            "PassRole+CreateLambda+Invoke": frozenset({"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}),
            "PassRole+CreateLambda+ExistingDynamo": frozenset({"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"}),
            "PassRole+CreateLambda+NewDynamo": frozenset({"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping", "dynamodb:CreateTable", "dynamodb:PutItem"}),
            "PassRole+GlueEndpoint": frozenset({"iam:PassRole", "glue:CreateDevEndpoint", "glue:GetDevEndpoint"}),
            "PassRole+CloudFormation": frozenset({"iam:PassRole", "cloudformation:CreateStack", "cloudformation:DescribeStacks"}),
            "PassRole+DataPipeline": frozenset({"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"}),
            "iam:CreateAccessKey": frozenset({"iam:CreateAccessKey"}),
            "iam:CreateLoginProfile": frozenset({"iam:CreateLoginProfile"}),
            "iam:UpdateLoginProfile": frozenset({"iam:UpdateLoginProfile"}),
            "iam:AttachUserPolicy": frozenset({"iam:AttachUserPolicy"}),
            "iam:AttachGroupPolicy": frozenset({"iam:AttachGroupPolicy"}),
            "iam:AttachRolePolicy": frozenset({"iam:AttachRolePolicy"}),
            "AssumeRole+AttachRolePolicy": frozenset({"sts:AssumeRole", "iam:AttachRolePolicy"}),
            "iam:PutGroupPolicy": frozenset({"iam:PutGroupPolicy"}),
            "iam:PutRolePolicy": frozenset({"iam:PutRolePolicy"}),
            "AssumeRole+PutRolePolicy": frozenset({"sts:AssumeRole", "iam:PutRolePolicy"}),
            "iam:PutUserPolicy": frozenset({"iam:PutUserPolicy"}),
            "iam:AddUserToGroup": frozenset({"iam:AddUserToGroup"}),
            "iam:UpdateAssumeRolePolicy": frozenset({"iam:UpdateAssumeRolePolicy"}),
            "AssumeRole+UpdateAssumeRolePolicy": frozenset({"sts:AssumeRole", "iam:UpdateAssumeRolePolicy"}),
        }

        try:
            # List all managed and inline policies
            policies = client.list_policies(Scope='Local', OnlyAttached=False)['Policies']

            for policy in policies:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']

                # Get the policy document
                policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

                # Check statements in the policy
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]  # Ensure it's a list for single statements

                for statement in statements:
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', '*')
                    if isinstance(actions, str):
                        actions = [actions]  # Convert single action to a list

                    # Match privilege escalation actions
                    matched_combinations = []
                    for comb_name, comb_actions in privilege_escalation_policies_combination.items():
                        if set(actions) & comb_actions:
                            matched_combinations.append(comb_name)

                    # Update the report based on matched combinations
                    if matched_combinations:
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[f"Policy '{policy_name}' allows privilege escalation with combinations: {matched_combinations}"] = False
                    else:
                        report.resource_ids_status[f"Policy '{policy_name}' does not allow privilege escalation"] = True

        except Exception as e:
            logging.error(f"Error while checking privilege escalation in policies: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["Error occurred while checking privilege escalation"] = False

        return report
