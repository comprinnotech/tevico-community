"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class sns_topics_kms_encryption_at_rest_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            sns_client = connection.client('sns')
            topics = sns_client.list_topics().get('Topics', [])

            if not topics:
                report.resource_ids_status['No SNS topics found'] = True
                return report

            for topic in topics:
                topic_arn = topic['TopicArn']
                try:
                    topic_attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)['Attributes']
                    kms_key_id = topic_attributes.get('KmsMasterKeyId')
                    # Mark as False if topic is unencrypted (no KMS key)
                    report.resource_ids_status[topic_arn] = False if not kms_key_id else True
                except (ClientError, BotoCoreError, Exception):
                    report.resource_ids_status[topic_arn] = False

            # Check passes if NO topics are unencrypted
            report.passed = all(report.resource_ids_status.values())

        except (ClientError, BotoCoreError, Exception):
            report.resource_ids_status['Error checking SNS topic encryption'] = False

        return report
