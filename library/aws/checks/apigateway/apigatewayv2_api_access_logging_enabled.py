import boto3

from tevico.app.entities.report.check_model import CheckReport
from tevico.app.entities.check.check import Check


class apigatewayv2_api_access_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        raise NotImplementedError