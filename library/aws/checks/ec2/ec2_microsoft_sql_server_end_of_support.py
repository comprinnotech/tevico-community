"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-29
"""

import boto3
from datetime import datetime
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class ec2_microsoft_sql_server_end_of_support(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
        client = connection.client('ec2')
        sts_client = connection.client('sts')

        try:
            account_number = sts_client.get_caller_identity()['Account']
            region = client.meta.region_name

            # Pagination for describe_instances
            reservations = []
            next_token = None
            while True:
                response = client.describe_instances(NextToken=next_token) if next_token else client.describe_instances()
                reservations.extend(response.get('Reservations', []))
                next_token = response.get('NextToken')
                if not next_token:
                    break

            # If no instances at all
            if not reservations:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EC2 instances found."
                    )
                )
                return report

            found_windows_instance = False

            for reservation in reservations:
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    ami_id = instance['ImageId']
                    instance_arn = f"arn:aws:ec2:{region}:{account_number}:instance/{instance_id}"
                    resource = AwsResource(arn=instance_arn)

                    if instance['State']['Name'] != 'running' or instance.get('Platform') != 'windows':
                        continue

                    found_windows_instance = True  # At least one Windows EC2 found

                    try:
                        ami_details = client.describe_images(ImageIds=[ami_id])['Images'][0]
                    except Exception:
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.UNKNOWN,
                                summary=f"Failed to describe AMI {ami_id} for instance {instance_id}."
                            )
                        )
                        continue

                    ami_name = ami_details.get('Name', '')
                    ami_description = ami_details.get('Description', '')

                    def extract_sql_version(text1, text2):
                        for version in ["2012", "2014", "2016", "2017", "2019", "2022"]:
                            if version in text1 or version in text2:
                                return version
                        return None

                    def calculate_eos(version):
                        eos_map = {
                            "2012": datetime(2022, 7, 12),
                            "2014": datetime(2024, 7, 9),
                            "2016": datetime(2026, 7, 14),
                            "2017": datetime(2027, 10, 12),
                            "2019": datetime(2030, 1, 9),
                            "2022": datetime(2033, 1, 12),
                        }
                        return eos_map.get(version)

                    sql_version = extract_sql_version(ami_name.lower(), ami_description.lower())
                    if not sql_version:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"Instance {instance_id} is not running Microsoft SQL Server."
                            )
                        )
                        continue

                    eos_date = calculate_eos(sql_version)
                    #if sql server reached end of support, mark as failed
                    if eos_date and eos_date < datetime.now():
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Instance {instance_id} is running SQL Server {sql_version}, which reached end of support on {eos_date.date()}."
                            )
                        )
                    else:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Instance {instance_id} is running SQL Server {sql_version}, supported until {eos_date.date()}."
                            )
                        )

            # If no Windows EC2s were found in any reservation
            if not found_windows_instance:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Windows-based EC2 instances found."
                    )
                )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error occurred during execution: {str(e)}"
                )
            )

        return report
