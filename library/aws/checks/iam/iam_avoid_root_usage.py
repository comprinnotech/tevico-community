"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""


# import boto3
# import datetime
# import pytz
# from dateutil import parser
# from tevico.engine.entities.report.check_model import CheckReport
# from tevico.engine.entities.check.check import Check

# class iam_avoid_root_usage(Check):
#     def execute(self, connection: boto3.Session) -> CheckReport:
#         report = CheckReport(name=__name__)
#         client = connection.client('iam')

#         try:
#             # Generate the credential report
#             client.generate_credential_report()
#             response = client.get_credential_report()['Content']
#             decoded_report = response.decode('utf-8').splitlines()

#             # Parse the CSV-like credential report
#             for row in decoded_report[1:]:
#                 user_info = row.split(',')
#                 if user_info[0] == "<root_account>":
#                     # Extract last access times
#                     password_last_used = user_info[4]
#                     access_key_1_last_used = user_info[6]
#                     access_key_2_last_used = user_info[9]

#                     last_accessed = None

#                     # Check when the root account was last accessed (password or access keys)
#                     if password_last_used != "not_supported":
#                         last_accessed = parser.parse(password_last_used)
#                     elif access_key_1_last_used != "N/A":
#                         last_accessed = parser.parse(access_key_1_last_used)
#                     elif access_key_2_last_used != "N/A":
#                         last_accessed = parser.parse(access_key_2_last_used)

#                     if last_accessed:
#                         days_since_accessed = (datetime.datetime.now(pytz.utc) - last_accessed).days
#                         print(f"Root user was last accessed {days_since_accessed} days ago on {last_accessed}.")
#                         report.resource_ids_status['RootAccount'] = True  # Root usage detected
#                         report.passed = False
#                     else:
#                         print("No information on when the root user was last accessed.")
#                         report.resource_ids_status['RootAccount'] = False  # No root usage detected
#                         report.passed = True

#                     break  # We only care about the root account, so stop after processing

#         except Exception as e:
#             print("Error in retrieving root account usage information")
#             print(str(e))
#             report.passed = False

#         return report



import boto3
import datetime
import pytz
from dateutil import parser
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Define maximum number of days allowed for root access
maximum_access_days = 1

class iam_avoid_root_usage(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
            # Generate the credential report
            client.generate_credential_report()
            response = client.get_credential_report()['Content']
            decoded_report = response.decode('utf-8').splitlines()

            # Parse the CSV-like credential report
            for row in decoded_report[1:]:
                user_info = row.split(',')
                if user_info[0] == "<root_account>":
                    # Extract last access times
                    password_last_used = user_info[4]
                    access_key_1_last_used = user_info[6]
                    access_key_2_last_used = user_info[9]

                    last_accessed = None

                    # Check when the root account was last accessed (password or access keys)
                    if password_last_used != "not_supported":
                        last_accessed = parser.parse(password_last_used)
                    elif access_key_1_last_used != "N/A":
                        last_accessed = parser.parse(access_key_1_last_used)
                    elif access_key_2_last_used != "N/A":
                        last_accessed = parser.parse(access_key_2_last_used)

                    if last_accessed:
                        days_since_accessed = (datetime.datetime.now(pytz.utc) - last_accessed).days
                        # print(f"Root user was last accessed {days_since_accessed} days ago on {last_accessed}.")

                        # Evaluate against maximum access days
                        if days_since_accessed <= maximum_access_days:
                            report.resource_ids_status['RootAccount'] = True  # Root usage detected
                            report.passed = False
                        else:
                            report.resource_ids_status['RootAccount'] = False  # No root usage detected
                            report.passed = True
                    else:
                        # print("No information on when the root user was last accessed.")
                        report.resource_ids_status['RootAccount'] = False  # No root usage detected
                        report.passed = True

                    break  # We only care about the root account, so stop after processing

        except Exception as e:
            # print("Error in retrieving root account usage information")
            # print(str(e))
            report.passed = False
            report.resource_ids_status['RootAccount'] = False  # Assume no usage detected in case of error

        return report
