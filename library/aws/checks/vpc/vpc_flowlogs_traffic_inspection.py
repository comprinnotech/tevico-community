"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check


class vpc_flowlogs_traffic_inspection(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            ec2_client = connection.client('ec2')

            # Collect all VPCs
            vpc_ids = []
            paginator = ec2_client.get_paginator('describe_vpcs')
            for page in paginator.paginate():
                vpc_ids.extend([vpc.get("VpcId") for vpc in page.get("Vpcs", [])])

            # If no VPCs found
            if not vpc_ids:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No VPCs found."
                    )
                )
                return report

            for vpc_id in vpc_ids:
                resource = GeneralResource(name=vpc_id)

                # Fetch flow logs for this VPC
                flow_logs = []
                paginator = ec2_client.get_paginator('describe_flow_logs')
                for page in paginator.paginate(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                ):
                    flow_logs.extend(page.get("FlowLogs", []))

                if not flow_logs:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.FAILED,
                            summary=f"VPC {vpc_id} does not have any flow logs configured."
                        )
                    )
                    continue

                # Filter active flow logs
                active_flow_logs = [
                    fl for fl in flow_logs if fl.get("FlowLogStatus", "").upper() == "ACTIVE"
                ]

                if not active_flow_logs:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.FAILED,
                            summary=f"VPC {vpc_id} has flow logs configured, but none are active."
                        )
                    )
                    continue

                # Collect traffic types
                active_traffic_types = {
                    fl.get("TrafficType", "").upper() for fl in active_flow_logs
                }

                # Check if ALL or both ACCEPT + REJECT exist
                if "ALL" in active_traffic_types or {"ACCEPT", "REJECT"} <= active_traffic_types:
                    status = CheckStatus.PASSED
                    summary = (
                        f"VPC {vpc_id} has active flow logs capturing all traffic "
                        f"(Traffic Types: {', '.join(active_traffic_types)})."
                    )
                else:
                    status = CheckStatus.FAILED
                    summary = (
                        f"VPC {vpc_id} does not have active flow logs capturing all traffic. "
                        f"Active Traffic Types: {', '.join(active_traffic_types) or 'None'}. "
                        "Flow logs must capture either all traffic (ALL) or both accepted and rejected traffic (ACCEPT and REJECT)."
                    )

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=resource,
                        status=status,
                        summary=summary
                    )
                )

        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"AWS API request failed. Unable to verify VPC flow logs: {str(e)}",
                    exception=str(e)
                )
            )
        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving VPCs or flow logs: {str(e)}",
                    exception=str(e)
                )
            )

        return report
