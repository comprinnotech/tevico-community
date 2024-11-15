"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""


import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_no_root_access_keys(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Print message indicating the function is starting
        print("Starting IAM and root access keys check...")

        # Initialize the check report
        report = CheckReport(name=__name__)

        # Create an IAM client
        client = connection.client('iam')

        try:
            # First check the root account for access keys (no UserName should be specified)
            print("Checking root account for access keys...")
            response = client.list_access_keys()

            # Initialize a flag to track if any keys are active for root
            has_active_root_keys = False

            # Iterate through the access keys associated with the root account
            for access_key in response['AccessKeyMetadata']:
                if access_key['Status'] == 'Active':
                    # If any access key is active, mark the check as failed
                    has_active_root_keys = True
                    report.passed = False
                    report.resource_ids_status['root_account'] = False
                    print(f"Active access key found for root account: {access_key['AccessKeyId']}")
                    break

            if not has_active_root_keys:
                print("No active access keys found for the root account.")
                report.resource_ids_status['root_account'] = True

            # Now check all IAM users for access keys
            print("Checking IAM users for access keys...")
            iam_users = client.list_users()['Users']

            # Iterate over all IAM users
            for user in iam_users:
                user_name = user['UserName']
                response = client.list_access_keys(UserName=user_name)

                has_active_iam_keys = False

                # Check each IAM user for active access keys
                for access_key in response['AccessKeyMetadata']:
                    if access_key['Status'] == 'Active':
                        has_active_iam_keys = True
                        report.passed = False
                        report.resource_ids_status[user_name] = False
                        print(f"Active access key found for IAM user '{user_name}': {access_key['AccessKeyId']}")
                        break

                if not has_active_iam_keys:
                    print(f"No active access keys found for IAM user '{user_name}'.")
                    report.resource_ids_status[user_name] = True

        except Exception as e:
            # Handle errors (for example, if listing access keys is not allowed)
            report.passed = False
            print(f"An error occurred: {str(e)}")

        return report
