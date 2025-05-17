"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-03-28
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class s3_bucket_acl_prohibited(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        s3_client = connection.client("s3")
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            paginator = s3_client.get_paginator("list_buckets")
            bucket_list = []

            for page in paginator.paginate():
                bucket_list.extend(page.get("Buckets", []))

            if not bucket_list:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No S3 buckets found."
                    )
                )
                return report  # Early exit if no buckets

            for bucket in bucket_list:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # First check if ObjectOwnership is set to BucketOwnerEnforced (which prohibits ACLs)
                    try:
                        ownership_response = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
                        ownership_rule = ownership_response.get("OwnershipControls", {}).get("Rules", [{}])[0]
                        object_ownership = ownership_rule.get("ObjectOwnership", "")
                        
                        if object_ownership == "BucketOwnerEnforced":
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=bucket_arn),
                                    status=CheckStatus.PASSED,
                                    summary=f"S3 bucket {bucket_name} has ACLs prohibited via BucketOwnerEnforced setting."
                                )
                            )
                            continue  # Skip to next bucket as this one passes
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'OwnershipControlsNotFoundError':
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=bucket_arn),
                                    status=CheckStatus.ERRORED,
                                    summary=f"S3 bucket {bucket_name} has no ownership controls set.",
                                    exception=str(e)
                                )
                            )
                        else:
                            raise  # Re-raise if it's a different error
                    
                    # Check the bucket ACL if ObjectOwnership is not BucketOwnerEnforced
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                    grants = acl_response.get("Grants", [])
                    
                    # Check for public or cross-account access in ACLs
                    has_public_access = False
                    has_cross_account_access = False
                    owner_id = acl_response.get("Owner", {}).get("ID", "")
                    
                    for grant in grants:
                        grantee = grant.get("Grantee", {})
                        grantee_type = grantee.get("Type", "")
                        
                        # Check for public access
                        if grantee_type == "Group" and grantee.get("URI") in [
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                        ]:
                            has_public_access = True
                            break
                        
                        # Check for cross-account access (excluding owner)
                        if grantee_type == "CanonicalUser" and grantee.get("ID") != owner_id:
                            has_cross_account_access = True
                    
                    if has_public_access:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} has public access configured via ACLs."
                            )
                        )
                    elif has_cross_account_access:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} has cross-account access configured via ACLs."
                            )
                        )
                    else:
                        # Check if Block Public Access is enabled at bucket level
                        try:
                            bpa_response = s3_client.get_public_access_block(Bucket=bucket_name)
                            public_access_block = bpa_response.get("PublicAccessBlockConfiguration", {})
                            
                            if (public_access_block.get("BlockPublicAcls", False) and
                                public_access_block.get("IgnorePublicAcls", False)):
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=AwsResource(arn=bucket_arn),
                                        status=CheckStatus.PASSED,
                                        summary=f"S3 bucket {bucket_name} has ACLs effectively prohibited via Block Public Access settings."
                                    )
                                )
                            else:
                                report.status = CheckStatus.FAILED
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=AwsResource(arn=bucket_arn),
                                        status=CheckStatus.FAILED,
                                        summary=f"S3 bucket {bucket_name} has ACLs enabled and Block Public Access settings are not fully configured."
                                    )
                                )
                        except ClientError as e:
                            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                                report.status = CheckStatus.FAILED   #It should not be unknown because ERROR message is known.
                                report.resource_ids_status.append(
                                    ResourceStatus(
                                        resource=AwsResource(arn=bucket_arn),
                                        status=CheckStatus.FAILED,
                                        summary=f"S3 bucket {bucket_name} has ACLs enabled and no Block Public Access configuration."
                                    )
                                )
                            else:
                                raise  # Re-raise if it's a different error
                
                except (BotoCoreError, ClientError) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=bucket_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Failed to retrieve ACL settings for S3 bucket {bucket_name}.",
                            exception=str(e)
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Encountered an error while retrieving S3 buckets.",
                    exception=str(e)
                )
            )

        return report
