"""
AUTHOR: RONIT CHAUHAN
DATE: 2024-10-17
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check
from datetime import datetime

class organizations_account_part_of_organizations(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        start_time = datetime.now()
        # print(f"[{start_time}] - Starting the check for AWS Organizations.")

        report = CheckReport(name=__name__)

        # Initialize the Organizations client
        org_client = connection.client('organizations')
        # print(f"[{datetime.now()}] - AWS Organizations client initialized.")
        
        findings = []
        
        try:
            # Fetch list of AWS Organizations
            # print(f"[{datetime.now()}] - Fetching list of AWS Organizations...")
            organizations_list = org_client.list_roots()['Roots']
            # print(f"[{datetime.now()}] - Retrieved {len(organizations_list)} organization(s).")
            
            for organization in organizations_list:
                org_id = organization['Id']
                org_arn = organization['Arn']
                org_status = organization['PolicyTypes'][0]['Status']  # Assuming status is found under 'PolicyTypes'

                # print(f"[{datetime.now()}] - Processing organization {org_id} with status {org_status}.")
                
                # Create a report for the organization
                org_report = {
                    "resource_id": org_id,
                    "resource_arn": org_arn,
                    "region": connection.region_name,
                }

                # Update this condition to reflect the correct status interpretation
                if org_status == "ENABLED":  # Change from "ACTIVE" to "ENABLED"
                    org_report["status"] = "PASS"
                    org_report["message"] = f"AWS Organization {org_id} contains this AWS account."
                    findings.append(org_report)
                    # print(f"[{datetime.now()}] - Organization {org_id} is ENABLED. Marking as PASS.")
                    report.status = ResourceStatus.PASSED
                    
                    # Fetch list of accounts in the organization
                    # print(f"[{datetime.now()}] - Fetching accounts for organization {org_id}...")
                    accounts = org_client.list_accounts()['Accounts']
                    # print(f"[{datetime.now()}] - Found {len(accounts)} accounts under organization {org_id}:")
                    for account in accounts:
                        # print(f"  - Account ID: {account['Id']}, Name: {account['Name']}, Email: {account['Email']}")
                        pass  # Commented out for output

                else:
                    org_report["status"] = "FAIL"
                    org_report["message"] = f"AWS Organization {org_id} is not in use for this AWS account."
                    findings.append(org_report)
                    # print(f"[{datetime.now()}] - Organization {org_id} is not ENABLED. Marking as FAIL.")
                    report.status = ResourceStatus.FAILED

            # Store findings in report metadata
            report.report_metadata = {"findings": findings}
            # print(f"[{datetime.now()}] - Findings have been recorded.")
            
        except Exception as e:
            # Handle potential exceptions (e.g., permissions issues)
            # print(f"[{datetime.now()}] - Exception occurred: {str(e)}")
            report.status = ResourceStatus.FAILED
            report.report_metadata = {"error": str(e)}

        end_time = datetime.now()
        # print(f"[{end_time}] - Completed the check for AWS Organizations. Duration: {end_time - start_time}")

        return report
    
    # Pass Condition: If the organization is ENABLED, it adds a "PASS" status confirming that the AWS Organization contains the AWS account.
    # Fail Condition: If the status is not "ENABLED", it adds a "FAIL" status that the AWS Organization is not in use.