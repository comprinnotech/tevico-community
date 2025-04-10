"""
AUTHOR: Prajwal G
EMAIL: prajwal.govindraja@comprinno.net
DATE: 2024-04-05
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_flowlogs_traffic_inspection(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # -------------------------------------------------------------------
        # Initializes the check report.
        # -------------------------------------------------------------------
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # -------------------------------------------------------------------
            # Set up AWS clients for EC2 and STS.
            # EC2 client: used to retrieve VPCs and flow logs.
            # STS client: used to retrieve account information (e.g. account ID).
            # -------------------------------------------------------------------
            ec2_client = connection.client('ec2')
            sts_client = connection.client('sts')

            # -------------------------------------------------------------------
            # Retrieves AWS account ID and region.
            # These values are used for constructing valid ARNs.
            # -------------------------------------------------------------------
            account_id = sts_client.get_caller_identity()['Account']
            region = ec2_client.meta.region_name

            # -------------------------------------------------------------------
            # Retrieves all VPCs in the account using pagination.
            # -------------------------------------------------------------------
            vpcs = []
            next_token = None
            while True:
                if next_token:
                    response = ec2_client.describe_vpcs(NextToken=next_token)
                else:
                    response = ec2_client.describe_vpcs()
                vpcs.extend(response.get("Vpcs", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break

            # -------------------------------------------------------------------
            # If no VPCs are found, mark the check as NOT_APPLICABLE,
            # append a corresponding ResourceStatus, and return the report.
            # -------------------------------------------------------------------
            if not vpcs:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No VPCs found in the account."
                    )
                )
                return report

            # -------------------------------------------------------------------
            # For each VPC, evaluate whether it has an active flow log capturing all traffic.
            # Acceptable cases:
            #   - A flow log with TrafficType "ALL"
            #   - OR separate active flow logs with TrafficType "ACCEPT" and "REJECT"
            # -------------------------------------------------------------------
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                vpc_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
                resource = AwsResource(arn=vpc_arn)

                # -------------------------------------------------------------------
                # Retrieve flow logs for the current VPC using pagination.
                # Use a filter on 'resource-id' to get only flow logs for this VPC.
                # -------------------------------------------------------------------
                try:
                    flow_logs = []
                    next_token_fl = None
                    while True:
                        if next_token_fl:
                            response = ec2_client.describe_flow_logs(
                                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}],
                                NextToken=next_token_fl
                            )
                        else:
                            response = ec2_client.describe_flow_logs(
                                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                            )
                        flow_logs.extend(response.get("FlowLogs", []))
                        next_token_fl = response.get("NextToken")
                        if not next_token_fl:
                            break
                except Exception as fl_e:
                    # -------------------------------------------------------------------
                    # Exception Handling for Flow Log Retrieval.
                    # If an error occurs while retrieving flow logs for this VPC,
                    # records the error and mark this VPC's result as UNKNOWN.
                    # -------------------------------------------------------------------
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving flow logs for VPC {vpc_id}: {str(fl_e)}",
                            exception=str(fl_e)
                        )
                    )
                    continue

                # -------------------------------------------------------------------
                # Determines which flow logs are active.
                # A flow log is considered active if its FlowLogStatus is "ACTIVE".
                # -------------------------------------------------------------------
                active_flow_logs = [fl for fl in flow_logs if fl.get("FlowLogStatus", "").upper() == "ACTIVE"]

                # -------------------------------------------------------------------
                # Collects the TrafficType values from active flow logs.
                # Valid TrafficType values are typically "ALL", "ACCEPT", or "REJECT".
                # -------------------------------------------------------------------
                active_traffic_types = {fl.get("TrafficType", "").upper() for fl in active_flow_logs}

                # -------------------------------------------------------------------
                # Determines if the VPC's flow logs captures all traffic.
                # Acceptable conditions:
                #   - There is at least one active flow log with TrafficType "ALL", or
                #   - Both "ACCEPT" and "REJECT" are present in the active flow logs.
                # -------------------------------------------------------------------
                if "ALL" in active_traffic_types or ({"ACCEPT", "REJECT"} <= active_traffic_types):
                    summary = (
                        f"VPC {vpc_id} has active flow logs capturing all traffic "
                        f"(Traffic Types: {', '.join(active_traffic_types)})."
                    )
                    status = CheckStatus.PASSED
                else:
                    summary = (
                        f"VPC {vpc_id} does not have active flow logs capturing all traffic. "
                        f"Active Traffic Types: {', '.join(active_traffic_types) if active_traffic_types else 'None'}. "
                        "Flow logs must capture either all traffic (ALL) or both accepted and rejected traffic (ACCEPT and REJECT)."
                    )
                    status = CheckStatus.FAILED
                    # Update overall report status to FAILED if any VPC fails the check.
                    report.status = CheckStatus.FAILED

                # -------------------------------------------------------------------
                # Append the result for this VPC to the report.
                # Each result includes the resource, its determined status, and a summary.
                # -------------------------------------------------------------------
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=resource,
                        status=status,
                        summary=summary
                    )
                )
                
        except Exception as e:
            # -------------------------------------------------------------------
            # Global Exception Handling.
            # If an error occurs during processing (e.g. retrieving VPCs), mark the overall check as UNKNOWN
            # and record the error details in the report.
            # -------------------------------------------------------------------
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving VPCs: {str(e)}",
                    exception=str(e)
                )
            )

        return report