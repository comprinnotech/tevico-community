"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_imdsv2_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the EC2 client using the provided connection
        ec2_client = connection.client('ec2')

        # Create a report object to store check results
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to True, will change if any instance is non-compliant
        report.resource_ids_status = []

        try:
            # Describe all EC2 instances
            response = ec2_client.describe_instances()
            reservations = response.get('Reservations', [])
            
            if not reservations:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.SKIPPED,
                        summary=f"No EC2 instances found."
                    )
                )
                #report.message = "No EC2 instances found."
                return report

            # Loop through instances
            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_arn = instance['IamInstanceProfile']['Arn']
                    metadata_options = instance.get('MetadataOptions', {})

                    # Check if IMDSv2 is enabled (HttpTokens == 'required')
                    if metadata_options.get('HttpTokens') == 'required':
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(Arn=instance_arn),
                                status=CheckStatus.PASSED,
                                summary=f"Instance {instance_id} has IMDSv2 enabled."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(Arn=instance_arn),
                                status=CheckStatus.FAILED,
                                summary=f"EC2 Instance {instance_id} does not have IMDSv2 enabled (HttpTokens set to {metadata_options.get('HttpTokens')})."
                            )
                        )
                        #report.message = f"EC2 Instance {instance_id} does not have IMDSv2 enabled (HttpTokens set to {metadata_options.get('HttpTokens')})."
        except Exception as e:
            # In case of an error, mark the check as failed and log the error
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.PASSED,
                    summary=f"Error while fetching EC2 instance metadata:",
                    exception=str(e)
                )
            )
            #report.message = f"Error while fetching EC2 instance metadata: {str(e)}"
        
        return report