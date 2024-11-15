"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class sns_topics_kms_encryption_at_rest_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        sns_client = connection.client('sns')

        topics = sns_client.list_topics()['Topics']

        for topic in topics:
            topic_arn = topic['TopicArn']
            
            try:
                topic_attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)['Attributes']
                kms_key_id = topic_attributes.get('KmsMasterKeyId', None)

                if kms_key_id:
                    report.resource_ids_status[topic_arn] = True
                else:
                    report.resource_ids_status[topic_arn] = False

            except sns_client.exceptions.NotFoundException:
                report.resource_ids_status[topic_arn] = False

        return report
