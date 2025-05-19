"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-31
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class eks_cluster_kms_cmk_encryption_in_secrets_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("eks")
            clusters = []
            next_token = None

            # Pagination for listing all EKS clusters
            while True:
                response = client.list_clusters(nextToken=next_token) if next_token else client.list_clusters()
                clusters.extend(response.get("clusters", []))
                next_token = response.get("nextToken")
                if not next_token:
                    break

            # If no EKS clusters exist, mark as NOT_APPLICABLE
            if not clusters:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EKS clusters found."
                    )
                )
                return report

            # Iterate over each cluster and check KMS encryption for secrets
            for cluster in clusters:
                cluster_desc = client.describe_cluster(name=cluster)["cluster"]
                cluster_arn = cluster_desc.get("arn")
                resource = AwsResource(arn=cluster_arn)

                try:
                    # Check if CMK encryption is enabled for secrets
                    encryption_configs = cluster_desc.get("encryptionConfig", [])
                    secrets_encrypted = any(
                        "provider" in config and config["provider"].get("keyArn") and "secrets" in config.get("resources", [])
                        for config in encryption_configs
                    )

                    if secrets_encrypted:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Secrets encryption with KMS CMK is enabled for cluster {cluster}."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Secrets encryption with KMS CMK is NOT enabled for cluster {cluster}."
                            )
                        )
                
                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=cluster_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking encryption for cluster {cluster}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error accessing EKS clusters: {str(e)}",
                    exception=str(e)
                )
            )

        return report
