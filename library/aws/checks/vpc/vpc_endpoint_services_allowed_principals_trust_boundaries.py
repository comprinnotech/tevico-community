"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3
import re

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_endpoint_services_allowed_principals_trust_boundaries(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ec2_client = connection.client('ec2')
        sts_client = connection.client('sts')  
        all_compliant = True  

        try:
            account_id = sts_client.get_caller_identity().get('Account')
            trusted_account_ids = [account_id]

            response = ec2_client.describe_vpc_endpoint_services()
            vpc_endpoint_services = response.get('ServiceDetails', [])

            for service in vpc_endpoint_services:
                allowed_principals = service.get('AllowedPrincipals', [])

                if not allowed_principals:
                    continue

                for principal in allowed_principals:
                    match = re.match(r"^[0-9]{12}$", principal)
                    principal_account_id = match.string if match else principal.split(":")[4]

                    if principal_account_id not in trusted_account_ids:
                        all_compliant = False
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[service['ServiceName']] = False
                        break

                if not all_compliant:
                    break

            if all_compliant:
                report.status = ResourceStatus.PASSED

            return report

        except Exception as e:
            report.status = ResourceStatus.FAILED
            return report

