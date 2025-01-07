"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class sns_topics_kms_encryption_at_rest_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Start with True

        try:
            sns_client = connection.client('sns')
            topics = sns_client.list_topics().get('Topics', [])

            if not topics:
                return report

            for topic in topics:
                topic_arn = topic['TopicArn']
                try:
                    topic_attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)['Attributes']
                    kms_key_id = topic_attributes.get('KmsMasterKeyId')
                    is_encrypted = bool(kms_key_id)
                    report.resource_ids_status[topic_arn] = is_encrypted

                    if not is_encrypted:
                        report.passed = False  # Fail if any topic is not encrypted

                except KeyError:
                    report.resource_ids_status[topic_arn] = False
                    report.passed = False

        except (ClientError, BotoCoreError, Exception):
            # Handle AWS API errors or other exceptions that occur during execution
            report.passed = False
            return report

        return report

