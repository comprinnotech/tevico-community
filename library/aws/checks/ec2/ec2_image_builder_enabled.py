"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-10
"""

from math import pi
import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_image_builder_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('imagebuilder')
        report.status = ResourceStatus.FAILED
        pipelines = client.list_image_pipelines()['imagePipelineList']
        for pipeline in pipelines:
            if pipeline.get('status') == 'ENABLED':
                report.status = ResourceStatus.PASSED
        return report        
