"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-06
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class sns_topics_kms_encryption_at_rest_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize SNS client and check report
        sns_client = connection.client('sns')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Pagination for listing all SNS topics
            topics = []
            next_token = None

            while True:
                response = sns_client.list_topics(NextToken=next_token) if next_token else sns_client.list_topics()
                topics.extend(response.get("Topics", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no SNS topics exist, mark as NOT_APPLICABLE
            if not topics:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="SNS Topics"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No SNS topics found in the account.",
                    )
                )
                return report

            # Check each topic for KMS encryption
            for topic in topics:
                topic_arn = topic["TopicArn"]

                try:
                    # Fetch topic attributes
                    topic_attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
                    kms_key_id = topic_attributes.get("KmsMasterKeyId")

                    if kms_key_id:
                        summary = f"SNS topic {topic_arn} is encrypted with KMS."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"SNS topic {topic_arn} is not encrypted with KMS."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED

                    # Append result to report
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=topic_arn),
                            status=status,
                            summary=summary,
                        )
                    )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=topic_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error fetching attributes for SNS topic {topic_arn}.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN

        except Exception as e:
            # Handle SNS topic listing errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="SNS Topics"),
                    status=CheckStatus.UNKNOWN,
                    summary="SNS topics listing error.",
                    exception=str(e)
                )
            )
        return report
