"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class ssm_managed_compliant_patching(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        ssm_client = connection.client('ssm')
        ec2_client = connection.client('ec2')

        try:
            response = ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )

            instance_ids = [instance['InstanceId'] for reservation in response['Reservations'] for instance in reservation['Instances']]

            if not instance_ids:
                report.passed = False
                report.resource_ids_status['SSM_COMPLIANT_PATCHING'] = False
                return report

            patch_response = ssm_client.describe_instance_patch_states(InstanceIds=instance_ids)

            compliance_resources = patch_response.get('InstancePatchStates', [])

            all_compliant = True

            for resource in compliance_resources:
                patch_compliance_status = resource['PatchComplianceStatus']
                if patch_compliance_status != "COMPLIANT":
                    all_compliant = False
                    break

            report.passed = all_compliant
            report.resource_ids_status['SSM_COMPLIANT_PATCHING'] = all_compliant

            if not any(status for status in report.resource_ids_status.values()):
                report.passed = False

        except Exception:
            report.passed = False
            report.resource_ids_status['SSM_COMPLIANT_PATCHING'] = False

        return report

