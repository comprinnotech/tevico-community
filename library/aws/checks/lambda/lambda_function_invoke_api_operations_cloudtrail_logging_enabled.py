"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-14
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class lambda_function_invoke_api_operations_cloudtrail_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED
        report.resource_ids_status = []
        lambda_client = connection.client("lambda")
        cloudtrail_client = connection.client("cloudtrail")

        try:
            lambda_functions = []
            next_token = None

            # Pagination for Lambda functions
            while True:
                response = lambda_client.list_functions(NextMarker=next_token) if next_token else lambda_client.list_functions()
                lambda_functions.extend(response.get("Functions", []))
                next_token = response.get("NextMarker")
                if not next_token:
                    break

            if not lambda_functions:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Lambda functions found in the account."
                    )
                )
                return report
            
            # Pagination for CloudTrail trails
            trails = []
            next_token = None
            while True:
                response = cloudtrail_client.describe_trails(NextToken=next_token) if next_token else cloudtrail_client.describe_trails()
                trails.extend(response.get("trailList", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break

            if not trails:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="No CloudTrails found in the account."
                    )
                )
                    
                return report

            trail_event_selectors = {}
            for trail in trails:
                # Skip organization trails as event selectors cannot be accessed
                if trail.get("IsOrganizationTrail", False):
                    continue
                trail_name = trail.get("Name")
                trail_arn = trail.get("TrailARN")
                selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
                event_selectors = selectors_response.get("EventSelectors", [])
                trail_event_selectors[trail_name] = event_selectors


            for function in lambda_functions:
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                try:
                    # Check if logging is enabled for this fucntion
                    function_logged = any(
                        any(
                            any(
                                resource.get("Type") == "AWS::Lambda::Function" and
                                any(arn == function_arn or arn.endswith("*") for arn in resource.get("Values", []))
                                for resource in selector.get("DataResources", [])
                            )
                            for selector in event_selectors
                        )
                        for event_selectors in trail_event_selectors.values()
                    )
                
                    status = CheckStatus.PASSED if function_logged else CheckStatus.FAILED
                    summary = (
                        f"Lambda function invoke API operations are being recorded by CloudTrail for function {function_name}."
                        if function_logged
                        else f"Lambda function invoke API operations are NOT being recorded by CloudTrail for function {function_name}."
                    )
                    
                    # Update report status only if it's passing (to maintain FAILED status if any function fails)

                    report.status = status
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=function_arn),
                            status=status,
                            summary=summary
                        )
                    )
                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=function_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking CloudTrail logging for Lambda function {function_name}: {str(e)}",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN
        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking Lambda CloudTrail logging: {str(e)}",
                    exception=str(e)
                )
            )

        return report