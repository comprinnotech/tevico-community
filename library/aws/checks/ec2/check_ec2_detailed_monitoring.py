import boto3
from botocore.exceptions import BotoCoreError, ClientError
from typing import Optional
from tevico.engine.entities.report.check_model import (
    CheckMetadata, CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check
from tevico.engine.entities.report.check_model import CheckMetadata
from tevico.engine.entities.report.check_model import (
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation
)

class check_ec2_detailed_monitoring(Check):
    def __init__(self, metadata: Optional[CheckMetadata] = None):
        # If metadata is None, provide a default instance
       def __init__(self, metadata: Optional[CheckMetadata] = None):
        if metadata is None:
            metadata = CheckMetadata(
                Provider="AWS",
                CheckID="ec2_detailed_monitoring",
                CheckTitle="EC2 Detailed Monitoring Check",
                CheckType=["Security"],
                ServiceName="EC2",
                SubServiceName="Instances",
                ResourceIdTemplate="{instance_id}",
                Severity="Low",
                ResourceType="AWS::EC2::Instance",
                Risk="Lack of detailed monitoring may reduce observability of instance behavior.",
                Remediation=Remediation(
        Code=RemediationCode(
            NativeIaC="",
            Terraform="resource \"aws_instance\" \"example\" {\n  monitoring = true\n}"
        ),
        Recommendation=RemediationRecommendation(
            Text="Enable detailed monitoring for EC2 instances.",
            Url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html"
        )
    ),
                Description="Checks whether EC2 instances have detailed monitoring enabled."
            )
        super().__init__(metadata=metadata)

    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2 = connection.client('ec2')
        name = self.__class__.__name__
        report = CheckReport(name=name, check_metadata=self.metadata)
        report.resource_ids_status = []

        try:
            # Use paginator
            paginator = ec2.get_paginator('describe_instances')
            instances = []
            for page in paginator.paginate():
                for res in page.get('Reservations', []):
                    instances.extend(res.get('Instances', []))

            if not instances:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EC2 instances found."
                    )
                )
            else:
                for inst in instances:
                    iid = inst['InstanceId']
                    state = inst.get('State', {}).get('Name', '').lower()
                    if state != 'running':
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=iid),
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"Instance {iid} is {state}, skipping."
                            )
                        )
                        continue

                    mon = inst.get('Monitoring', {}).get('State', 'disabled')
                    if mon == 'enabled':
                        status = CheckStatus.PASSED
                        summary = f"Detailed monitoring enabled for {iid}."
                    else:
                        status = CheckStatus.FAILED
                        summary = f"Detailed monitoring NOT enabled for {iid}."
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=iid),
                            status=status,
                            summary=summary
                        )
                    )

            # Determine overall status
            if any(rs.status == CheckStatus.FAILED for rs in report.resource_ids_status):
                report.status = CheckStatus.FAILED
            else:
                report.status = CheckStatus.PASSED

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            err_msg = (
                e.response.get('Error', {}).get('Message', str(e))
                if isinstance(e, ClientError) else str(e)
            )
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving EC2 monitoring status.",
                    exception=err_msg
                )
            )

        return report
