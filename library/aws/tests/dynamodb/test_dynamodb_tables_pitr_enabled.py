"""
Test suite for the dynamodb_tables_pitr_enabled check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 03-06-2025
"""

import boto3
from botocore.stub import Stubber
from botocore.exceptions import BotoCoreError, ClientError
import pytest
from tevico.engine.entities.report.check_model import (
    CheckMetadata, CheckStatus, Remediation, RemediationCode, RemediationRecommendation
)

from library.aws.checks.dynamodb.dynamodb_tables_pitr_enabled import dynamodb_tables_pitr_enabled


def build_check_metadata():
    """Returns a sample CheckMetadata object with predefined values."""
    return CheckMetadata(
        Provider="aws",
        CheckID="dynamodb_tables_pitr_enabled",
        CheckTitle="DynamoDB tables should have Point-in-Time Recovery (PITR) enabled",
        CheckType=["Reliability"],
        ServiceName="DynamoDB",
        SubServiceName="Tables",
        ResourceIdTemplate="{TableArn}",
        Severity="Medium",
        ResourceType="AWS::DynamoDB::Table",
        Risk="Without PITR, accidental writes or deletes cannot be recovered beyond the standard backup schedule.",
        RelatedUrl="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws dynamodb update-continuous-backups --table-name <table-name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
            ),
            Recommendation=RemediationRecommendation(
                Text="Enable Point-in-Time Recovery (PITR) for critical DynamoDB tables to protect against accidental data loss.",
                Url="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html"
            )
        ),
        Description="Check whether DynamoDB tables have Point-in-Time Recovery (PITR) enabled to ensure recoverability."
    )


class DummySession:
    """Dummy boto3 session wrapper for injecting stubbed clients."""
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        return self._client


def test_no_dynamodb_tables():
    """Should return NOT_APPLICABLE when no tables exist."""
    client = boto3.client("dynamodb", region_name="us-east-1")
    stubber = Stubber(client)

    # Simulate no DynamoDB tables
    stubber.add_response("list_tables", {"TableNames": []})
    stubber.activate()

    check = dynamodb_tables_pitr_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.status == CheckStatus.NOT_APPLICABLE
    assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE


def test_all_tables_with_pitr_enabled():
    """Should return PASSED when all tables have PITR enabled."""
    client = boto3.client("dynamodb", region_name="us-east-1")
    stubber = Stubber(client)

    # Simulate one table with PITR enabled
    stubber.add_response("list_tables", {"TableNames": ["table1"]})
    stubber.add_response("describe_table", {
        "Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
        }
    })
    stubber.add_response("describe_continuous_backups", {
        "ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "ENABLED",
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED"
            }
        }
    })

    stubber.activate()

    check = dynamodb_tables_pitr_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED
    assert "PITR enabled" in (report.resource_ids_status[0].summary or "")


def test_some_tables_with_pitr_disabled():
    """Should return FAILED when a table has PITR disabled."""
    client = boto3.client("dynamodb", region_name="us-east-1")
    stubber = Stubber(client)

    # Simulate one table with PITR disabled
    stubber.add_response("list_tables", {"TableNames": ["table1"]})
    stubber.add_response("describe_table", {
        "Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
        }
    })
    stubber.add_response("describe_continuous_backups", {
        "ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "DISABLED",
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "DISABLED"
            }
        }
    })

    stubber.activate()

    check = dynamodb_tables_pitr_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "PITR disabled" in (report.resource_ids_status[0].summary or "")


def test_pitr_check_raises_exception():
    """Should return UNKNOWN if an exception occurs during PITR check."""
    client = boto3.client("dynamodb", region_name="us-east-1")
    stubber = Stubber(client)

    # Simulate normal response for list_tables and describe_table
    stubber.add_response("list_tables", {"TableNames": ["table1"]})
    stubber.add_response("describe_table", {
        "Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
        }
    })

    # Do not add describe_continuous_backups response to trigger error
    stubber.activate()

    # Override the method to raise a BotoCoreError
    def raise_exception(*args, **kwargs):
        raise BotoCoreError()

    client.describe_continuous_backups = raise_exception  # type: ignore[assignment]

    check = dynamodb_tables_pitr_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession(client))  # type: ignore[arg-type]

    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN


def test_list_tables_fails():
    """Should raise ClientError if list_tables API fails."""
    class FailingSession:
        def client(self, service_name):
            if service_name in ["dynamodb", "kms"]:
                raise ClientError(
                    {"Error": {"Code": "SimulatedException", "Message": "Simulated failure"}},
                    operation_name=service_name,
                )

    check = dynamodb_tables_pitr_enabled(metadata=build_check_metadata())

    # Expecting a ClientError when list_tables fails
    with pytest.raises(ClientError):
        check.execute(connection=FailingSession())  # type: ignore[arg-type]