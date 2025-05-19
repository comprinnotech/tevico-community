"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_service_endpoint_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        
        # Initialize the check report.
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        
        try:
            # Set up AWS clients for EC2.
            ec2_client = connection.client('ec2')
            
            # Retrieve all VPCs using pagination.
            vpcs = []
            paginator = ec2_client.get_paginator('describe_vpcs')
            for page in paginator.paginate():
                vpcs.extend(page.get("Vpcs", []))
            
            # If no VPCs found, mark check as NOT_APPLICABLE.
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

            # Define critical services that should have endpoints
            critical_services = ["s3"]  # At minimum, S3 is required

            # Evaluate each VPC for service endpoints.
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                vpc_name = next((tag.get("Value") for tag in vpc.get("Tags", []) if tag.get("Key") == "Name"), "")
                vpc_display = f"{vpc_id} ({vpc_name})" if vpc_name else vpc_id
                
                # VPCs don't have traditional ARNs, use the ID as resource identifier
                resource = GeneralResource(name=vpc_id)

                # Get endpoints for this specific VPC using filters
                endpoints = []
                paginator = ec2_client.get_paginator('describe_vpc_endpoints')
                for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
                    endpoints.extend(page.get("VpcEndpoints", []))
                
                # Filter for available endpoints
                available_endpoints = [ep for ep in endpoints if ep.get("State", "").lower() == "available"]
                
                # Extract service names from available endpoints
                service_names = []
                for ep in available_endpoints:
                    service_name = ep.get("ServiceName", "")
                    # Extract the service name from the full service name (e.g., com.amazonaws.region.s3 -> s3)
                    parts = service_name.split(".")
                    if len(parts) >= 1:
                        service_names.append(parts[-1].lower())
                
                # Check if all critical services have endpoints
                missing_critical = [svc for svc in critical_services if svc not in service_names]
                
                # Determine result based on critical service endpoints
                if not missing_critical:
                    summary = (
                        f"VPC {vpc_display} has all required service endpoints. "
                        f"Available services: {', '.join(service_names)}"
                    )
                    status = CheckStatus.PASSED
                else:
                    report.status = CheckStatus.FAILED
                    
                    if available_endpoints:
                        summary = (
                            f"VPC {vpc_display} is missing critical service endpoints: {', '.join(missing_critical)}. "
                            f"Currently available: {', '.join(service_names)}. "
                            f"At minimum, S3 endpoint is required."
                        )
                    else:
                        summary = (
                            f"VPC {vpc_display} does not have any service endpoints. "
                            f"At minimum, S3 endpoint is required."
                        )
                    
                    status = CheckStatus.FAILED

                # Add result to report
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=resource,
                        status=status,
                        summary=summary
                    )
                )

        except (BotoCoreError, ClientError) as e:
            # AWS API Exception Handling
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"AWS API request failed. Unable to verify VPC endpoints: {str(e)}",
                    exception=str(e)
                )
            )
        except Exception as e:
            # Global Exception Handling
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking VPC endpoints: {str(e)}",
                    exception=str(e)
                )
            )
            
        return report
