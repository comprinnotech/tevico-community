"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-14
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class vpc_flowlogs_analyze_logs(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        ec2_client = connection.client('ec2')
        logs_client = connection.client('logs')

        try:
            # Get all VPCs
            paginator = ec2_client.get_paginator('describe_vpcs')
            vpcs = []
            
            for page in paginator.paginate():
                vpcs.extend(page.get('Vpcs', []))
            
            if not vpcs:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No VPCs found."
                    )
                )
                return report

            # Check each VPC for flow logs
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                
                # Get flow logs for this VPC
                response = ec2_client.describe_flow_logs(Filters=[{
                    'Name': 'resource-id',
                    'Values': [vpc_id]
                }])
                
                flow_logs = response.get('FlowLogs', [])
                
                if not flow_logs:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=vpc_id),
                            status=CheckStatus.FAILED,
                            summary=f"VPC {vpc_id} does not have flow logs configured."
                        )
                    )
                    continue
                
                # Check if any flow log is configured to send to CloudWatch Logs
                cloudwatch_logs_configured = False
                s3_logs_configured = False
                
                for flow_log in flow_logs:
                    log_destination_type = flow_log.get('LogDestinationType')
                    
                    # Check if logs are sent to CloudWatch Logs
                    if log_destination_type == 'cloud-watch-logs':
                        log_group_name = flow_log.get('LogGroupName')
                        if log_group_name:
                            # Verify the log group exists and has metric filters (indicating analysis)
                            try:
                                # Check if log group exists
                                logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                                
                                # Check for metric filters (indicating analysis)
                                metric_filters = logs_client.describe_metric_filters(
                                    logGroupName=log_group_name
                                ).get('metricFilters', [])
                                
                                if metric_filters:
                                    cloudwatch_logs_configured = True
                                    report.resource_ids_status.append(
                                        ResourceStatus(
                                            resource=GeneralResource(name=vpc_id),
                                            status=CheckStatus.PASSED,
                                            summary=f"VPC {vpc_id} has flow logs configured with CloudWatch Logs group '{log_group_name}' and has metric filters for analysis."
                                        )
                                    )
                                    break
                                else:
                                    # Log group exists but no metric filters
                                    report.resource_ids_status.append(
                                        ResourceStatus(
                                            resource=GeneralResource(name=vpc_id),
                                            status=CheckStatus.FAILED,
                                            summary=f"VPC {vpc_id} has flow logs configured with CloudWatch Logs group '{log_group_name}', but no metric filters are set up for analysis."
                                        )
                                    )
                            except (BotoCoreError, ClientError) as e:
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=GeneralResource(name=vpc_id),
                                        status=CheckStatus.UNKNOWN,
                                        summary=f"VPC {vpc_id} has flow logs configured with CloudWatch Logs group '{log_group_name}', but the log group could not be verified: {str(e)}"
                                    )
                                )
                    # Note if logs are sent to S3
                    elif log_destination_type == 's3':
                        s3_logs_configured = True
                
                # Check if we already have a status for this VPC
                if not cloudwatch_logs_configured and not any(r.resource.name == vpc_id if isinstance(r.resource, GeneralResource) else False for r in report.resource_ids_status):
                    if s3_logs_configured:
                        # If logs are sent to S3 but not CloudWatch, note this in the summary
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=vpc_id),
                                status=CheckStatus.FAILED,
                                summary=f"VPC {vpc_id} has flow logs configured to send to S3, but not to CloudWatch Logs. While S3 storage is valid, this check specifically requires CloudWatch Logs for real-time analysis capabilities."
                            )
                        )
                    else:
                        # If logs are not sent to CloudWatch or S3
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=vpc_id),
                                status=CheckStatus.FAILED,
                                summary=f"VPC {vpc_id} has flow logs, but they are not configured to send to CloudWatch Logs for analysis."
                            )
                        )

        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking VPC flow logs: {str(e)}",
                    exception=str(e)
                )
            )
        
        return report
