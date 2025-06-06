"""
Test suite for the dynamodb_tables_kms_cmk_encryption_enabled check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 03-06-2025
"""

# Required libraries
import datetime
import boto3
from botocore.stub import Stubber
from botocore.exceptions import BotoCoreError, ClientError
from boto3.session import Session as Boto3Session

import pytest

# Import the check and related models
from library.aws.checks.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled import dynamodb_tables_kms_cmk_encryption_enabled
from tevico.engine.entities.report.check_model import (
    CheckMetadata, CheckStatus, Remediation, RemediationCode, RemediationRecommendation
)

# Helper function to build static metadata for the check
def build_check_metadata():
    return CheckMetadata(
        Provider="aws",
        CheckID="dynamodb_tables_kms_cmk_encryption_enabled",
        CheckTitle="DynamoDB tables should use CMK encryption",
        CheckType=["Security"],
        ServiceName="DynamoDB",
        SubServiceName="Tables",
        ResourceIdTemplate="{TableArn}",
        Severity="High",
        ResourceType="AWS::DynamoDB::Table",
        Risk="Data could be accessible without customer-managed encryption.",
        RelatedUrl="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
        Remediation=Remediation(
            Code=RemediationCode(
                CLI="aws dynamodb update-table --table-name <table-name> --sse-specification Enabled=true,KMSMasterKeyId=<key-arn>"
            ),
            Recommendation=RemediationRecommendation(
                Text="Enable encryption using a customer-managed KMS key (CMK) on DynamoDB tables.",
                Url="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html"
            )
        ),
        Description="Check if DynamoDB tables are encrypted with a customer-managed KMS key."
    )

# Dummy session class to return stubbed boto3 clients
class DummySession(Boto3Session):
    def __init__(self, clients):
        self._clients = clients

    def client(self, service_name):
        return self._clients[service_name]

# Test when there are no DynamoDB tables
def test_check_with_no_tables():
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")
    kms = boto3.client("kms", region_name="us-east-1")

    # Stub the list_tables call to return an empty list
    dynamodb_stubber = Stubber(dynamodb)
    dynamodb_stubber.add_response("list_tables", {"TableNames": []})
    dynamodb_stubber.activate()

    check = dynamodb_tables_kms_cmk_encryption_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession({"dynamodb": dynamodb, "kms": kms}))

    # No tables => Not applicable
    assert report.status == CheckStatus.NOT_APPLICABLE
    assert report.resource_ids_status[0].status == CheckStatus.NOT_APPLICABLE

# Test when table uses Customer-Managed CMK
def test_check_with_customer_managed_cmk():
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")
    kms = boto3.client("kms", region_name="us-east-1")

    dynamodb_stubber = Stubber(dynamodb)
    kms_stubber = Stubber(kms)

    # Stub table listing and its SSE with CMK
    dynamodb_stubber.add_response("list_tables", {"TableNames": ["table1"]})
    dynamodb_stubber.add_response("describe_table", {
        "Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/table1",
            "SSEDescription": {
                "Status": "ENABLED",
                "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc123"
            }
        }
    })

    # Simulate that the key is managed by customer
    kms_stubber.add_response("describe_key", {
        "KeyMetadata": {
            "KeyId": "abc123",
            "KeyManager": "CUSTOMER",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/abc123",
            "Enabled": True,
            "CreationDate": datetime.datetime(2020, 1, 1)
        }
    })

    dynamodb_stubber.activate()
    kms_stubber.activate()

    check = dynamodb_tables_kms_cmk_encryption_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession({"dynamodb": dynamodb, "kms": kms}))

    # Customer-managed CMK => PASSED
    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED

# Test when table uses AWS-managed KMS key
def test_check_with_aws_managed_key():
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")
    kms = boto3.client("kms", region_name="us-east-1")

    dynamodb_stubber = Stubber(dynamodb)
    kms_stubber = Stubber(kms)

    # Stub table and encryption info
    dynamodb_stubber.add_response("list_tables", {"TableNames": ["table1"]})
    dynamodb_stubber.add_response("describe_table", {
        "Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/table1",
            "SSEDescription": {
                "Status": "ENABLED",
                "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/aws-managed"
            }
        }
    })

    # Stub key info indicating it's AWS-managed
    kms_stubber.add_response("describe_key", {
        "KeyMetadata": {
            "KeyId": "abc123",
            "KeyManager": "AWS",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/abc123",
            "Enabled": True,
            "CreationDate": datetime.datetime(2020, 1, 1)
        }
    })

    dynamodb_stubber.activate()
    kms_stubber.activate()

    check = dynamodb_tables_kms_cmk_encryption_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession({"dynamodb": dynamodb, "kms": kms}))

    # AWS-managed => FAILED
    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED

# Test when DynamoDB table has no SSE config (owned key)
def test_check_with_dynamodb_owned_key():
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")
    stubber = Stubber(dynamodb)

    # No SSEDescription simulates use of AWS-owned key
    stubber.add_response("list_tables", {"TableNames": ["table1"]})
    stubber.add_response("describe_table", {
        "Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
            # No SSEDescription
        }
    })

    stubber.activate()

    check = dynamodb_tables_kms_cmk_encryption_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession({"dynamodb": dynamodb, "kms": boto3.client("kms")}))

    # AWS-owned key => FAILED
    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "owned key" in (report.resource_ids_status[0].summary or "")

# Simulate boto3 failure when creating client (e.g. permission or config error)
def test_check_with_boto_exception_on_list_tables():
    class FailingSession:
        def client(self, service_name):
            if service_name in ["dynamodb", "kms"]:
                raise ClientError(
                    {"Error": {"Code": "SimulatedException", "Message": "Simulated failure"}},
                    operation_name=service_name,
                )

    check = dynamodb_tables_kms_cmk_encryption_enabled(metadata=build_check_metadata())

    # The check should raise an exception due to client failure
    with pytest.raises(ClientError):
        check.execute(connection=FailingSession())  # type: ignore[arg-type]

# Simulate exception while processing a specific table
def test_check_with_exception_in_table_processing():
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")
    stubber = Stubber(dynamodb)

    # Table listed but describe_table fails (e.g. AccessDenied)
    stubber.add_response("list_tables", {"TableNames": ["table1"]})
    stubber.add_client_error("describe_table", service_error_code="AccessDeniedException")

    stubber.activate()

    check = dynamodb_tables_kms_cmk_encryption_enabled(metadata=build_check_metadata())
    report = check.execute(connection=DummySession({"dynamodb": dynamodb, "kms": boto3.client("kms")}))

    # Describe table fails => UNKNOWN
    assert report.status == CheckStatus.UNKNOWN
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
