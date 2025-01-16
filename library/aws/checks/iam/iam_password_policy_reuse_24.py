"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_password_policy_reuse_24(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('iam')
            account_password_policy = client.get_account_password_policy()
            password_policy = account_password_policy['PasswordPolicy']
            reuse_prevention = password_policy.get('ReusePrevention', 0)

            report.status = reuse_prevention >= 24
            report.resource_ids_status['password_policy'] = reuse_prevention >= 24

        except client.exceptions.NoSuchEntityException:
            report.status = ResourceStatus.FAILED
            report.resource_ids_status['password_policy'] = False
        except Exception:
            report.status = ResourceStatus.FAILED

        return report
