import boto3  # type: ignore
import pytest  # type: ignore
from unittest.mock import patch, MagicMock
import importlib.util
import sys
from pathlib import Path
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)


# === Dynamic import to bypass 'lambda' reserved keyword issue ===
file_path = (
    Path(__file__).resolve().parent.parent
    / "library"
    / "aws"
    / "checks"
    / "lambda"
    / "check_lambda_deprecated_runtime.py"
)
spec = importlib.util.spec_from_file_location(
    "check_lambda_deprecated_runtime", str(file_path)
)
module = importlib.util.module_from_spec(spec) # type: ignore
sys.modules["check_lambda_deprecated_runtime"] = module
spec.loader.exec_module(module) # type: ignore

# Access the class from the module
check_lambda_deprecated_runtime = module.check_lambda_deprecated_runtime

# === Pytest Fixtures and Tests ===

matadata = CheckMetadata(
    Provider="AWS",
    CheckID="lambda_deprecated_runtime",
    CheckTitle="Deprecated Lambda Runtime Check",
    CheckType=["Security"],
    ServiceName="Lambda",
    SubServiceName="Runtime",
    ResourceIdTemplate="{function_name}",
    Severity="Medium",
    ResourceType="AWS::Lambda::Function",
    Risk="Deprecated runtimes may pose security or stability risks.",
    Remediation=Remediation(
        Code=RemediationCode(
            NativeIaC="",
            Terraform="""resource "aws_lambda_function" "example" {
  function_name = "example"
  runtime       = "python3.11"
}""",
        ),
        Recommendation=RemediationRecommendation(
            Text="Migrate to a supported Lambda runtime.",
            Url="https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
        ),
    ),
    Description="Checks whether any Lambda functions are using deprecated runtimes.",
)


@pytest.fixture
def mock_boto_session():
    return boto3.Session(region_name="us-east-1")


@patch("boto3.Session.client")
def test_check_with_deprecated_runtime(mock_client, mock_boto_session):
    mock_lambda = MagicMock()
    mock_client.return_value = mock_lambda

    mock_lambda.get_paginator.return_value.paginate.return_value = [
        {
            "Functions": [
                {"FunctionName": "test-lambda-old", "Runtime": "python2.7"},
                {"FunctionName": "test-lambda-good", "Runtime": "python3.9"},
            ]
        }
    ]

    check = check_lambda_deprecated_runtime(matadata)
    report = check.execute(mock_boto_session)

    assert report.status == CheckStatus.FAILED
    assert len(report.resource_ids_status) == 2
    failed = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]
    assert failed[0].resource.name == "test-lambda-old"


@patch("boto3.Session.client")
def test_check_with_no_lambda_functions(mock_client, mock_boto_session):
    mock_lambda = MagicMock()
    mock_client.return_value = mock_lambda
    mock_lambda.get_paginator.return_value.paginate.return_value = [{"Functions": []}]

    check = check_lambda_deprecated_runtime(matadata)
    report = check.execute(mock_boto_session)

    assert report.status == CheckStatus.PASSED
    assert len(report.resource_ids_status) == 0
