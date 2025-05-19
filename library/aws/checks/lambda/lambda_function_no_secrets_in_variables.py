"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-05-02
"""

import boto3
import re
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class lambda_function_no_secrets_in_variables(Check):
    SECRET_PATTERN = re.compile(
        r'(?i)'
        r'password|'
        r'secret|'
        r'credential|'
        r'token|'
        r'api[\s_-]?key|'
        r'access[\s_-]?key|'
        r'client[\s_-]?id|'
        r'client[\s_-]?secret|'
        r'bearer|'
        r'oauth|'
        r'aws_access_key_id|'
        r'aws_secret_access_key|'
        r'aws_session_token|'
        r'PRIVATE[\s_-]?KEY|'
        r'certificate|'
        r'connection[\s_-]?string'
    )

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        lambda_client = connection.client("lambda")

        try:
            functions = []
            next_token = None

            # Pagination for listing Lambda functions
            while True:
                response = lambda_client.list_functions(Marker=next_token) if next_token else lambda_client.list_functions()
                functions.extend(response.get("Functions", []))
                next_token = response.get("NextMarker")
                if not next_token:
                    break

            if not functions:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Lambda functions found."
                    )
                )
                return report

            for function in functions:
                func_name = function["FunctionName"]
                func_arn = function["FunctionArn"]
                resource = AwsResource(arn=func_arn)

                try:
                    config = lambda_client.get_function_configuration(FunctionName=func_name)
                    env_vars = config.get("Environment", {}).get("Variables", {})

                    if not env_vars:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"No environment variables found for function '{func_name}'."
                            )
                        )
                        continue

                    has_secret = any(
                        self.SECRET_PATTERN.search(key) or self.SECRET_PATTERN.search(value)
                        for key, value in env_vars.items()
                    )

                    if has_secret:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Potential secrets detected in environment variables of function '{func_name}'."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"No secrets detected in environment variables of function '{func_name}'."
                            )
                        )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving configuration for function '{func_name}'.",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Unexpected error while listing Lambda functions: {str(e)}",
                    exception=str(e)
                )
            )

        return report
