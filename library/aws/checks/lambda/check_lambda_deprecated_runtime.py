import boto3  # type: ignore
from typing import Optional
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
from tevico.engine.entities.report.check_model import (
    CheckMetadata, CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class check_lambda_deprecated_runtime(Check):
    def __init__(self, metadata: Optional[CheckMetadata] = None):
        super().__init__(metadata=metadata)

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("lambda")
        name = self.__class__.__name__
        report = CheckReport(name=name, check_metadata=self.metadata)

        deprecated_runtimes = {
            "nodejs10.x", "nodejs12.x", "python2.7", "dotnetcore2.1", "ruby2.5",
            "java8", "go1.x", "nodejs6.10"
        }

        try:
            paginator = client.get_paginator("list_functions")
            found_any = False

            for page in paginator.paginate():
                functions = page.get("Functions", [])
                if not functions:
                    continue
                found_any = True

                for function in functions:
                    fn_name = function["FunctionName"]
                    runtime = function.get("Runtime", "unknown")

                    if runtime in deprecated_runtimes:
                        status = CheckStatus.FAILED
                        summary = f"Lambda function {fn_name} uses deprecated runtime: {runtime}"
                    else:
                        status = CheckStatus.PASSED
                        summary = f"Lambda function {fn_name} is using supported runtime: {runtime}"

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=fn_name),
                            status=status,
                            summary=summary
                        )
                    )

            if not found_any:
                return CheckReport(
                    status=CheckStatus.PASSED,
                    name=name,
                    check_metadata=self.metadata,
                    status_extended="No Lambda functions found in this region/account.",
                    resource_id=None,
                    resource_arn=None,
                )
            else:
                report.status = (
                    CheckStatus.FAILED
                    if any(rs.status == CheckStatus.FAILED for rs in report.resource_ids_status)
                    else CheckStatus.PASSED
                )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to fetch Lambda functions.",
                    exception=str(e)
                )
            )

        return report
