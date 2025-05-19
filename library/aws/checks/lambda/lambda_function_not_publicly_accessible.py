"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-31
"""

import boto3
import json
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class lambda_function_not_publicly_accessible(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("lambda")
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default status
        report.resource_ids_status = []

        try:
            functions = []
            next_token = None

            # Paginate through Lambda functions
            while True:
                response = client.list_functions(Marker=next_token) if next_token else client.list_functions()
                functions.extend(response.get("Functions", []))
                next_token = response.get("Marker")
                if not next_token:
                    break

            # If no Lambda functions exist, mark as NOT_APPLICABLE
            if not functions:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Lambda functions found.",
                    )
                )
                return report

            # Check each function's policy for public access
            for function in functions:
                function_name = function["FunctionName"]
                function_arn = function["FunctionArn"]

                try:
                    policy_response = client.get_policy(FunctionName=function_name)
                    policy_json = policy_response.get("Policy", "{}")
                    policy_statements = json.loads(policy_json).get("Statement", [])

                    # Check for public access
                    is_public = any(
                        statement.get("Effect") == "Allow" and
                        (statement.get("Principal") == "*" or "AWS" in statement.get("Principal", {}) and statement["Principal"]["AWS"] == "*")
                        for statement in policy_statements
                    )

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=function_arn),
                            status=CheckStatus.FAILED if is_public else CheckStatus.PASSED,
                            summary=f"Lambda function {function_name} is {'publicly accessible' if is_public else 'private'}.",
                        )
                    )

                    if is_public:
                        report.status = CheckStatus.FAILED  # At least one function is public

                except ClientError as e:
                    error_code = e.response["Error"]["Code"]

                    if error_code == "ResourceNotFoundException":
                        # If no policy exists for the function it is assumed private
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=function_arn),
                                status=CheckStatus.PASSED,
                                summary=f"Lambda function {function_name} is private.",
                            )
                        )
                    else:
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=function_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Error retrieving policy for {function_name}: {str(e)}",
                                exception=str(e),
                            )
                        )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Unexpected error: {str(e)}",
                    exception=str(e),
                )
            )

        return report
