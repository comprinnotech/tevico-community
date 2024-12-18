"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-10
"""

from math import pi
import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class ec2_image_builder_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('imagebuilder')
        report = CheckReport(name=__name__)
        
        pipelines = client.list_image_pipelines().get('imagePipelineList', [])
        report.passed = any(pipeline.get('status') == 'ENABLED' for pipeline in pipelines)
        
        return report
