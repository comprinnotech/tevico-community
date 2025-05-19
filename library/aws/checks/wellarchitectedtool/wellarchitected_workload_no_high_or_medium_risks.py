"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-15
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class wellarchitected_workload_no_high_or_medium_risks(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []
        report.status = CheckStatus.PASSED  # Default status

        client = connection.client("wellarchitected")
        workloads = []
        next_token = None

        try:
            # Pagination to collect all workloads first
            while True:
                response = client.list_workloads(NextToken=next_token) if next_token else client.list_workloads()
                workloads.extend(response.get("WorkloadSummaries", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no workloads exist
            if not workloads:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Well-Architected workloads found."
                    )
                )
                return report

            # Process each workload to check for High or Medium risks
            for workload in workloads:
                workload_id = workload.get("WorkloadId")
                workload_name = workload.get("WorkloadName")
                workload_arn = workload.get("WorkloadArn")
                resource=AwsResource(arn=workload_arn)

                try: 

                    # List lens reviews associated with workload
                    lens_reviews = []
                    lens_next_token = None

                    while True:
                        lens_reviews_response = client.list_lens_reviews(
                            WorkloadId=workload_id,
                            NextToken=lens_next_token
                        ) if lens_next_token else client.list_lens_reviews(WorkloadId=workload_id)
                        
                        lens_reviews.extend(lens_reviews_response.get("LensReviewSummaries", []))
                        lens_next_token = lens_reviews_response.get("NextToken")

                        if not lens_next_token:
                            break
                    
                    has_high_or_medium_risks = False
                    for lens_review in lens_reviews:
                        lens_alias = lens_review.get("LensAlias")

                        if lens_alias:
                            review = client.get_lens_review(WorkloadId=workload_id, LensAlias=lens_alias)
                            risk_counts = review.get("LensReview", {}).get("RiskCounts", {})
                            high_risk_count = risk_counts.get("HIGH")
                            medium_risk_count = risk_counts.get("MEDIUM")

                            if high_risk_count > 0 or medium_risk_count > 0:
                                has_high_or_medium_risks = True
                                break

                    if has_high_or_medium_risks:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Workload '{workload_name}' has {high_risk_count} HIGH and {medium_risk_count} MEDIUM risks."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Workload '{workload_name}' has no HIGH or MEDIUM risks."
                            )
                        )
                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"An error occurred while checking workload '{workload_name}': {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"An error occurred while checking Well-Architected workloads: {str(e)}",
                    exception=str(e)
                )
            )

        return report
