"""
Test suite for ec2_image_builder_enabled check.

AUTHOR: Ninad Lunge
EMAIL: ninad.lunge@comprinno.net
DATE: 05-06-2025
"""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import (
    CheckStatus, CheckMetadata,
    Remediation, RemediationCode, RemediationRecommendation
)
from library.aws.checks.ec2.ec2_image_builder_enabled import ec2_image_builder_enabled

class TestEc2ImageBuilderEnabled:
    """Test cases for EC2 Image Builder pipeline enabled check."""

    def setup_method(self):
        """Set up test method with metadata and mock session/client."""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="ec2_image_builder_enabled",
            CheckTitle="EC2 Image Builder Pipeline Enabled",
            CheckType=["security", "compliance"],
            ServiceName="imagebuilder",
            SubServiceName="image-pipeline",
            ResourceIdTemplate="",
            Severity="medium",
            ResourceType="ec2-image-builder-pipeline",
            Risk="No enabled EC2 Image Builder pipelines may lead to unmanaged image creation",
            RelatedUrl="https://docs.aws.amazon.com/imagebuilder/latest/userguide/what-is-image-builder.html",
            Remediation=Remediation(
                Code=RemediationCode(
                    CLI="aws imagebuilder update-image-pipeline --image-pipeline-arn <value> --status ENABLED",
                    Terraform='resource "aws_imagebuilder_image_pipeline" "example" {\n  status = "ENABLED"\n}',
                    NativeIaC=None,
                    Other=None
                ),
                Recommendation=RemediationRecommendation(
                    Text="Enable at least one EC2 Image Builder pipeline to manage custom images",
                    Url="https://docs.aws.amazon.com/imagebuilder/latest/userguide/manage-image-pipelines.html"
                )
            ),
            Description="Checks if at least one EC2 Image Builder pipeline is enabled.",
            Categories=["security", "compliance"]
        )

        self.check = ec2_image_builder_enabled(metadata)
        self.mock_session = MagicMock()
        self.mock_client = MagicMock()
        self.mock_session.client.return_value = self.mock_client

    def test_enabled_pipeline_found(self):
        """Test when at least one pipeline is ENABLED."""
        self.mock_client.list_image_pipelines.side_effect = [
            {
                "imagePipelineList": [
                    {"status": "DISABLED", "name": "pipeline1"},
                    {"status": "ENABLED", "name": "pipeline2"},
                ],
                "nextToken": None
            }
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.PASSED
        assert "EC2 Image Builder pipeline is enabled" in (report.resource_ids_status[0].summary or "")

    def test_no_pipelines_found(self):
        """Test when no image pipelines exist."""
        self.mock_client.list_image_pipelines.return_value = {
            "imagePipelineList": [],
            "nextToken": None
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "No EC2 Image Builder pipelines found" in (report.resource_ids_status[0].summary or "")

    def test_no_enabled_pipelines(self):
        """Test when pipelines exist but none are ENABLED."""
        self.mock_client.list_image_pipelines.return_value = {
            "imagePipelineList": [
                {"status": "DISABLED", "name": "pipeline1"},
                {"status": "DISABLED", "name": "pipeline2"},
            ],
            "nextToken": None
        }

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.FAILED
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.FAILED
        assert "No EC2 Image Builder pipelines are in ENABLED state" in (report.resource_ids_status[0].summary or "")

    def test_pagination_handling(self):
        """Test pagination handling in list_image_pipelines."""
        self.mock_client.list_image_pipelines.side_effect = [
            {
                "imagePipelineList": [{"status": "DISABLED", "name": "pipeline1"}],
                "nextToken": "token1"
            },
            {
                "imagePipelineList": [{"status": "ENABLED", "name": "pipeline2"}],
                "nextToken": None
            }
        ]

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.PASSED
        assert any(r.summary and "enabled" in r.summary.lower() for r in report.resource_ids_status)

    def test_client_error_handling(self):
        """Test when client raises a ClientError."""
        self.mock_client.list_image_pipelines.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "Internal service error"}}, 
            "ListImagePipelines"
        )

        report = self.check.execute(self.mock_session)

        assert report.status == CheckStatus.UNKNOWN
        assert len(report.resource_ids_status) == 1
        assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN
        assert "Error checking EC2 Image Builder pipelines" in (report.resource_ids_status[0].summary or "")