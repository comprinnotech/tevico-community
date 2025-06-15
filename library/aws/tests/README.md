# Tevico Test Framework

This README provides guidance on writing tests for Tevico checks, using the IAM password policy lowercase check as an example.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Creating Test Cases](#creating-test-cases)
- [Example: IAM Password Policy Lowercase Check](#example-iam-password-policy-lowercase-check)
- [Common Testing Patterns](#common-testing-patterns)
- [Running Tests](#running-tests)

## Overview

Tevico's test framework uses pytest to validate the functionality of security checks. Each check should have corresponding test cases that verify its behavior under different scenarios.

## Test Structure

Tests should be organized in a directory structure that mirrors the checks:

```
library/aws/
├── checks/
│   └── iam/
│       └── iam_password_policy_lowercase.py
└── tests/
    ├── __init__.py
    └── iam/
        ├── __init__.py
        └── test_iam_password_policy_lowercase.py
```

## Creating Test Cases

Follow these steps to create test cases for a check:

1. **Create the test file**: Name it `test_[check_name].py` in the corresponding directory
2. **Import necessary modules**:
   - The check class
   - pytest and unittest.mock
   - Required Tevico models (CheckStatus, CheckMetadata, etc.)
3. **Create a test class**: Name it `Test[CheckClassName]`
4. **Implement setup_method**: Initialize the check with required metadata
5. **Write test methods**: Cover all possible scenarios and edge cases
6. **Mock AWS responses**: Use MagicMock to simulate AWS API responses
7. **Verify results**: Assert that the check returns the expected status and messages

## Example: IAM Password Policy Lowercase Check

The IAM password policy lowercase check verifies if the AWS account password policy requires at least one lowercase letter. Here's how we test it:

### Test Scenarios

1. **Password policy requires lowercase**: Should PASS
2. **Password policy doesn't require lowercase**: Should FAIL
3. **Password policy missing lowercase setting**: Should FAIL
4. **No password policy exists**: Should FAIL
5. **API error occurs**: Should return UNKNOWN

### Test Implementation

```python
"""
Test for IAM password policy lowercase check.
"""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from library.aws.checks.iam.iam_password_policy_lowercase import iam_password_policy_lowercase
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata
from tevico.engine.entities.report.check_model import Remediation, RemediationCode, RemediationRecommendation


class TestIamPasswordPolicyLowercase:
    """Test cases for IAM password policy lowercase check."""

    def setup_method(self):
        """Set up test method."""
        # Create a mock metadata object for the check
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="iam_password_policy_lowercase",
            CheckTitle="IAM Password Policy Requires Lowercase Characters",
            CheckType=["security"],
            ServiceName="iam",
            SubServiceName="password-policy",
            ResourceIdTemplate="arn:aws:iam::{account_id}:password-policy",
            Severity="medium",
            ResourceType="iam-password-policy",
            Risk="Passwords without lowercase characters are easier to guess",
            RelatedUrl="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws iam update-account-password-policy --require-lowercase-characters",
                    Terraform="resource \"aws_iam_account_password_policy\" \"strict\" {\n  require_lowercase_characters = true\n}",
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Configure IAM password policy to require at least one lowercase letter",
                    Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                )
            ),
            Description="Checks if the IAM password policy requires at least one lowercase letter",
            Categories=["security", "compliance"]
        )
        
        self.check = iam_password_policy_lowercase(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client
        
        # Set up the exceptions attribute on the mock client
        self.mock_client.exceptions = MagicMock()
        # Create a custom NoSuchEntityException for testing
        class NoSuchEntityException(Exception):
            pass
        self.mock_client.exceptions.NoSuchEntityException = NoSuchEntityException

    def test_password_policy_requires_lowercase(self):
        """Test when password policy requires lowercase characters."""
        # Mock the response for a policy that requires lowercase
        self.mock_client.get_account_password_policy.return_value = {
            'PasswordPolicy': {
                'RequireLowercaseCharacters': True
            }
        }

        # Execute the check
        report = self.check.execute(self.mock_session)

        # Verify the results
        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "enforces the use of at least one lowercase letter" in report.resource_ids_status[0].summary

    def test_password_policy_does_not_require_lowercase(self):
        """Test when password policy does not require lowercase characters."""
        # Mock the response for a policy that doesn't require lowercase
        self.mock_client.get_account_password_policy.return_value = {
            'PasswordPolicy': {
                'RequireLowercaseCharacters': False
            }
        }

        # Execute the check
        report = self.check.execute(self.mock_session)

        # Verify the results
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does not enforce the use of at least one lowercase letter" in report.resource_ids_status[0].summary

    def test_password_policy_missing_lowercase_setting(self):
        """Test when password policy exists but doesn't specify lowercase requirement."""
        # Mock the response for a policy that doesn't specify lowercase requirement
        self.mock_client.get_account_password_policy.return_value = {
            'PasswordPolicy': {
                # RequireLowercaseCharacters is missing
            }
        }

        # Execute the check
        report = self.check.execute(self.mock_session)

        # Verify the results
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "does not enforce the use of at least one lowercase letter" in report.resource_ids_status[0].summary

    def test_no_password_policy_exists(self):
        """Test when no password policy exists."""
        # Set up the NoSuchEntityException
        self.mock_client.get_account_password_policy.side_effect = self.mock_client.exceptions.NoSuchEntityException()

        # Execute the check
        report = self.check.execute(self.mock_session)

        # Verify the results
        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "No custom IAM password policy is configured" in report.resource_ids_status[0].summary

    def test_client_error_handling(self):
        """Test error handling when a ClientError occurs."""
        # Mock a ClientError with proper structure
        error_response = {'Error': {'Code': 'SomeError', 'Message': 'An error occurred'}}
        self.mock_client.get_account_password_policy.side_effect = ClientError(error_response, 'GetAccountPasswordPolicy')

        # Execute the check
        report = self.check.execute(self.mock_session)

        # Verify the results
        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "An error occurred while retrieving the IAM password policy" in report.resource_ids_status[0].summary
```

## Common Testing Patterns

### Mocking AWS API Responses

```python
# Success response
self.mock_client.some_method.return_value = {
    'SomeKey': 'SomeValue'
}

# Exception response
self.mock_client.some_method.side_effect = ClientError(
    {'Error': {'Code': 'SomeError', 'Message': 'Error message'}},
    'OperationName'
)

# Custom exception
self.mock_client.exceptions = MagicMock()
self.mock_client.exceptions.CustomException = Exception
self.mock_client.some_method.side_effect = self.mock_client.exceptions.CustomException()
```

### Verifying Check Results

```python
# Check passed
assert report.status == CheckStatus.PASSED
assert report.resource_ids_status[0].status == CheckStatus.PASSED

# Check failed
assert report.status == CheckStatus.FAILED
assert report.resource_ids_status[0].status == CheckStatus.FAILED

# Check unknown
assert report.status == CheckStatus.UNKNOWN
assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN

# Verify message content
assert "expected message text" in report.resource_ids_status[0].summary
```

## Running Tests

Run tests using pytest with poetry:

```bash
# Run a specific test file
poetry run pytest ./library/aws/tests/iam/test_iam_password_policy_lowercase.py -v

# Run all tests in a directory
poetry run pytest ./library/aws/tests/iam/ -v

# Run all tests
poetry run pytest ./library/aws/tests/ -v
```

The `-v` flag provides verbose output showing each test case result.
