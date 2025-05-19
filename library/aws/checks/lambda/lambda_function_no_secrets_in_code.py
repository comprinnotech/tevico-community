"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-28
"""

import boto3
import re
import zipfile
import io
import requests
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class lambda_function_no_secrets_in_code(Check):
    # Precompiled regex patterns for detecting secrets
    SECRET_PATTERN = re.compile(
        r'(?i)'
        r'password\s*=\s*["\']?.{6,}["\']?|'
        r'secret\s*=\s*["\']?.{6,}["\']?|'
        r'credential\s*=\s*["\']?.{6,}["\']?|'
        r'token\s*=\s*["\']?[A-Za-z0-9\-_]{8,}["\']?|'
        r'key\s*=\s*["\']?[A-Za-z0-9]{16,}["\']?|'
        r'auth\s*=\s*["\']?.{6,}["\']?|'
        r'certificate\s*=\s*["\']?.{6,}["\']?|'
        r'private[\s_-]?key|'
        r'connection[\s_-]?string|'
        r'jdbc|'
        r'mongodb(\+srv)?://|'
        r'postgres(ql)?://|'
        r'mysql://|'
        r'sqlserver://|'
        r'oracle://|'
        r'api[\s_-]?key|'
        r'access[\s_-]?key|'
        r'client[\s_-]?id|'
        r'client[\s_-]?secret|'
        r'bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+|'
        r'oauth|'
        r'aws_access_key_id|'
        r'aws_secret_access_key|'
        r'aws_session_token'
    )
        
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
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
                    # Get code location
                    code = lambda_client.get_function(FunctionName=func_name)
                    code_location = code.get("Code", {}).get("Location")

                    if not code_location:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.UNKNOWN,
                                summary=f"No code location found for function {func_name}."
                            )
                        )
                        continue

                    # Download deployment package
                    response = requests.get(code_location)
                    if response.status_code != 200:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.UNKNOWN,
                                summary=f"Failed to download Lambda code for {func_name}, status code {response.status_code}"
                            )
                        )
                        continue
                    
                    with zipfile.ZipFile(io.BytesIO(response.content)) as zipped:
                        has_secret = False
                        for file_info in zipped.infolist():
                            if file_info.filename.endswith((".py", ".js", ".ts", ".env", ".json", ".sh", ".yml", ".yaml")):
                                with zipped.open(file_info.filename) as f:
                                    try:
                                        content = f.read().decode(errors="ignore")
                                        if self.SECRET_PATTERN.search(content):
                                            has_secret = True
                                            break
                                    except Exception:
                                        continue  # Ignore binary or unreadable files

                    if has_secret:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Lambda function '{func_name}' code contains potential hardcoded secrets."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Lambda function '{func_name}' code has no detected hardcoded secrets."
                            )
                        )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error processing function {func_name}: {str(e)}",
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
