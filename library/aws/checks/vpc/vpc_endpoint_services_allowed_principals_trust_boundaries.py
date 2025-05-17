"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-14
"""

import boto3
import re
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_endpoint_services_allowed_principals_trust_boundaries(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        
        try:
            ec2_client = connection.client('ec2')
            sts_client = connection.client('sts')

            # Get current account ID
            account_id = sts_client.get_caller_identity().get('Account')
            trusted_account_ids = [account_id]  # Add other trusted accounts if needed

            # Get VPC endpoint services created by the account (not AWS services)
            # Use describe_vpc_endpoint_service_configurations instead of describe_vpc_endpoint_services
            paginator = ec2_client.get_paginator('describe_vpc_endpoint_service_configurations')
            vpc_endpoint_services = []
            
            for page in paginator.paginate():
                vpc_endpoint_services.extend(page.get('ServiceConfigurations', []))

            if not vpc_endpoint_services:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No VPC endpoint services created in the account."
                    )
                )
                return report

            # Check each VPC endpoint service
            for service in vpc_endpoint_services:
                
                    service_name = service.get('ServiceName', 'Unknown')
                    service_id = service.get('ServiceId', 'Unknown')
                    
                    # Get allowed principals for this service
                    try:
                        allowed_principals_response = ec2_client.describe_vpc_endpoint_service_permissions(
                            ServiceId=service_id
                        )
                        allowed_principals = allowed_principals_response.get('AllowedPrincipals', [])
                        allowed_principals = [p.get('Principal', '') for p in allowed_principals]
                    except (BotoCoreError, ClientError) as e:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=service_name),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Error retrieving allowed principals for VPC endpoint service {service_id} ({service_name}): {str(e)}",
                                exception=str(e)
                            )
                        )
                        continue

                    if not allowed_principals:
                        # No principals allowed means no untrusted principals
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=service_name),
                                status=CheckStatus.PASSED,
                                summary=f"VPC endpoint service {service_id} ({service_name}) has no allowed principals."
                            )
                        )
                        continue

                    untrusted_principals = []
                    
                    for principal in allowed_principals:
                        try:
                            # Check if principal is just an account ID (12 digits)
                            match = re.match(r"^[0-9]{12}$", principal)
                            if match:
                                principal_account_id = principal
                            else:
                                # Extract account ID from ARN format
                                principal_parts = principal.split(":")
                                if len(principal_parts) >= 5:
                                    principal_account_id = principal_parts[4]
                                else:
                                    # Invalid format, consider untrusted
                                    untrusted_principals.append(principal)
                                    continue

                            if principal_account_id not in trusted_account_ids:
                                untrusted_principals.append(principal)
                        except Exception:
                            # If we can't parse the principal, consider it untrusted
                            untrusted_principals.append(f"{principal} (parsing error)")

                    if untrusted_principals:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=service_name),
                                status=CheckStatus.FAILED,
                                summary=f"VPC endpoint service {service_id} ({service_name}) allows untrusted principals: {', '.join(untrusted_principals)}"
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=service_name),
                                status=CheckStatus.PASSED,
                                summary=f"VPC endpoint service {service_id} ({service_name}) only allows trusted principals."
                            )
                        )

        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking VPC endpoint services: {str(e)}",
                    exception=str(e)
                )
            )
        except Exception as e:
            # Catch any other exceptions and set to UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Unexpected error during check execution: {str(e)}",
                    exception=str(e)
                )
            )
        
        return report
