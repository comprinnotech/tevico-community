"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-28
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check


class vpc_flowlogs_enable_logging(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("ec2")

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            vpcs = []
            next_token = None
            account_id = connection.client("sts").get_caller_identity().get("Account")

            # Fetch all VPCs with pagination
            while True:
                response = client.describe_vpcs(NextToken=next_token) if next_token else client.describe_vpcs()
                vpcs.extend(response.get("Vpcs", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break  # Exit loop when no more pages

            if not vpcs:
                # No VPCs found, mark as NOT_APPLICABLE
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="VPC"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No VPCs found in the region."
                    )
                )
                return report

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                vpc_arn = f"arn:aws:ec2::{account_id}:vpc/{vpc_id}"

                try:
                    # Check if Flow Logs are enabled for this VPC
                    flow_logs = client.describe_flow_logs(
                        Filter=[{"Name": "resource-id", "Values": [vpc_id]}]
                    ).get("FlowLogs", [])

                    if flow_logs:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=vpc_arn),
                                status=CheckStatus.PASSED,
                                summary=f"VPC {vpc_id} has Flow Logs enabled."
                            )
                        )

                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=vpc_arn),
                                status=CheckStatus.FAILED,
                                summary=f"VPC {vpc_id} does not have Flow Logs enabled."
                            )
                        )

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=vpc_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking Flow Logs for VPC {vpc_id}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching VPCs: {str(e)}",
                    exception=str(e)
                )
            )

        return report
