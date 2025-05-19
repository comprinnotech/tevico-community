"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class eks_cluster_logging_enabled(Check):
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

            #if no clusters exist, mark check as not applicable
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

            for cluster in clusters:
                cluster_desc = client.describe_cluster(name=cluster)["cluster"]
                cluster_arn = cluster_desc.get("arn", f"arn:aws:eks:{region}:{account_id}:cluster/{cluster}")
                resource = AwsResource(arn=cluster_arn)

                try:
                    
                    # Check logging configuration
                    logging_config = cluster_desc.get("logging", {}).get("clusterLogging", [])
                    logging_enabled = any(log.get("enabled", False) for log in logging_config)

                    status = CheckStatus.PASSED if logging_enabled else CheckStatus.FAILED
                    summary = f"Logging {'enabled' if logging_enabled else 'not enabled'} for cluster {cluster}."

                    report.resource_ids_status.append(
                        ResourceStatus(resource=resource, status=status, summary=summary)
                    )

                    if not logging_enabled:
                        report.status = CheckStatus.FAILED  # Mark check as FAILED if any cluster lacks logging

                except Exception as e:
                    error_msg = f"Error retrieving logging status for cluster {cluster}: {str(e)}"
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
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=error_msg,
                    exception=str(e)
                )
            )

        return report
