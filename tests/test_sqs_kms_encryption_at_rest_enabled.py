import unittest
from unittest.mock import patch, MagicMock
from library.aws.checks.sqs.sqs_kms_encryption_at_rest_enabled import sqs_kms_encryption_at_rest_enabled
from tevico.engine.entities.report.check_model import CheckStatus


class TestSqsKmsEncryptionAtRestEnabled(unittest.TestCase):

    @patch("library.aws.checks.sqs.sqs_kms_encryption_at_rest_enabled.boto3.client")
    def test_encryption_enabled(self, mock_boto_client):
        mock_sqs = MagicMock()
        mock_boto_client.return_value = mock_sqs

        mock_sqs.list_queues.return_value = {
            "QueueUrls": ["https://sqs.us-east-1.amazonaws.com/123456789012/encrypted-queue"]
        }

        mock_sqs.get_queue_attributes.return_value = {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:us-east-1:123456789012:encrypted-queue",
                "KmsMasterKeyId": "alias/aws/sqs"
            }
        }

        session = MagicMock()
        session.client.return_value = mock_sqs

        check = sqs_kms_encryption_at_rest_enabled(metadata={})
        report = check.execute(session)

        self.assertEqual(report.status, CheckStatus.PASSED)
        self.assertEqual(len(report.resource_ids_status), 1)
        self.assertEqual(report.resource_ids_status[0].status, CheckStatus.PASSED)

    @patch("library.aws.checks.sqs.sqs_kms_encryption_at_rest_enabled.boto3.client")
    def test_encryption_not_enabled(self, mock_boto_client):
        mock_sqs = MagicMock()
        mock_boto_client.return_value = mock_sqs

        mock_sqs.list_queues.return_value = {
            "QueueUrls": ["https://sqs.us-east-1.amazonaws.com/123456789012/plain-queue"]
        }

        mock_sqs.get_queue_attributes.return_value = {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:us-east-1:123456789012:plain-queue"
                # No KmsMasterKeyId
            }
        }

        session = MagicMock()
        session.client.return_value = mock_sqs

        check = sqs_kms_encryption_at_rest_enabled(metadata={})
        report = check.execute(session)

        self.assertEqual(report.status, CheckStatus.FAILED)
        self.assertEqual(len(report.resource_ids_status), 1)
        self.assertEqual(report.resource_ids_status[0].status, CheckStatus.FAILED)

    @patch("library.aws.checks.sqs.sqs_kms_encryption_at_rest_enabled.boto3.client")
    def test_no_queues(self, mock_boto_client):
        mock_sqs = MagicMock()
        mock_boto_client.return_value = mock_sqs

        mock_sqs.list_queues.return_value = {
            "QueueUrls": []
        }

        session = MagicMock()
        session.client.return_value = mock_sqs

        check = sqs_kms_encryption_at_rest_enabled(metadata={})
        report = check.execute(session)

        self.assertEqual(report.status, CheckStatus.NOT_APPLICABLE)
        self.assertEqual(len(report.resource_ids_status), 1)
        self.assertEqual(report.resource_ids_status[0].status, CheckStatus.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
