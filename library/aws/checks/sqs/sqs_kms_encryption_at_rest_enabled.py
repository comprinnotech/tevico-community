"""
AUTHOR: Gunjan-katre-comprinno
EMAIL: gunjan.katre@comprinno.net
DATE: 2025-05-20
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class sqs_kms_encryption_at_rest_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        sqs_client = connection.client('sqs')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Fetch all SQS queue URLs
            response = sqs_client.list_queues()
            queue_urls = response.get("QueueUrls", [])

            if not queue_urls:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="SQS Queues"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No SQS queues found in the account."
                    )
                )
                return report

            for queue_url in queue_urls:
                try:
                    attrs = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["All"]
                    )["Attributes"]

                    kms_key_id = attrs.get("KmsMasterKeyId")
                    queue_arn = attrs.get("QueueArn")

                    if kms_key_id:
                        summary = f"SQS queue {queue_arn} is encrypted with KMS key: {kms_key_id}."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"SQS queue {queue_arn} is not encrypted with KMS."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=queue_arn),
                            status=status,
                            summary=summary
                        )
                    )

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=queue_url),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error fetching attributes for SQS queue {queue_url}.",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="SQS Queues"),
                    status=CheckStatus.UNKNOWN,
                    summary="SQS queue listing error.",
                    exception=str(e)
                )
            )

        return report
