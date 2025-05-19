"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class eks_control_plane_endpoint_access_restricted(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED unless a failure occurs
        report.resource_ids_status = []

        try:
            client = connection.client("eks")
            account_id = connection.client("sts").get_caller_identity()["Account"]
            region = client.meta.region_name

            clusters = []
            next_token = None

            # Fetch all clusters using pagination
            while True:
                response = client.list_clusters(nextToken=next_token) if next_token else client.list_clusters()
                clusters.extend(response.get("clusters", []))
                next_token = response.get("nextToken")
                if not next_token:
                    break  # Exit loop when no more pages
            
            if not clusters:
                # No EKS clusters found, mark as NOT_APPLICABLE
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EKS clusters found in the account."
                    )
                )
                return report

            for cluster in clusters:
                cluster_desc = client.describe_cluster(name=cluster)["cluster"]
                cluster_arn = cluster_desc.get("arn", f"arn:aws:eks:{region}:{account_id}:cluster/{cluster}")
                resource = AwsResource(arn=cluster_arn)
                try:
                    
                    # Check control plane endpoint access
                    endpoint_config = cluster_desc.get("resourcesVpcConfig", {})
                    public_access_enabled = endpoint_config.get("endpointPublicAccess", True)

                    status = CheckStatus.FAILED if public_access_enabled else CheckStatus.PASSED
                    summary = f"Public endpoint access is {'enabled' if public_access_enabled else 'restricted'} for cluster {cluster}."

                    report.resource_ids_status.append(
                        ResourceStatus(resource=resource, status=status, summary=summary)
                    )

                    if public_access_enabled:
                        report.status = CheckStatus.FAILED  # Mark check as FAILED if any cluster has public access enabled

                except Exception as e:
                    error_msg = f"Error checking endpoint access for cluster {cluster}: {str(e)}"
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=error_msg,
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            error_msg = f"Error accessing EKS clusters: {str(e)}"
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="EKS"),
                    status=CheckStatus.UNKNOWN,
                    summary=error_msg,
                    exception=str(e)
                )
            )

        return report
