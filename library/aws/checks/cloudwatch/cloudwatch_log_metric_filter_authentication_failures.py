"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-13
"""

import boto3
import logging
import re

from requests import PreparedRequest, get

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_authentication_failures(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize CloudWatch client
        client = connection.client('logs')
        
        report = CheckReport(name=__name__)
        
        # Initialize report status as 'Passed' unless we find a missing filter
        report.passed = True
        report.resource_ids_status = {}

        # Define the custom pattern for authentication failure (ConsoleLogin + Failed authentication)
        pattern = r"\$\.eventName\s*=\s*.?ConsoleLogin.+\$\.errorMessage\s*=\s*.?Failed authentication.?"
        
        try:
            # Get all log groups in the account
            log_groups = []
            next_token = None

            while True:
                # Fetch log groups with pagination
                response = client.describe_log_groups(nextToken=next_token) if next_token else client.describe_log_groups()
                log_groups.extend(response.get('logGroups', []))
                next_token = response.get('nextToken', None)

                if not next_token:
                    break

            # Track if any log group has a matching filter
            any_matching_filter_found = False

            # Check for Metric Filters for authentication failures in each log group
            for log_group in log_groups:
                log_group_name = log_group['logGroupName']
                
                # Fetch metric filters for the log group
                filters = client.describe_metric_filters(logGroupName=log_group_name)
                
                # Look for filters related to authentication failures with the custom pattern
                matching_filters = []
                print(matching_filters)
                for filter in filters.get('metricFilters', []):
                    filter_pattern = filter.get('filterPattern', '')
                    # Check if the filter pattern matches the custom pattern for authentication failures
                    if re.search(pattern, filter_pattern):
                        matching_filters.append(filter.get('filterName'))

                if matching_filters:
                    # If a matching filter is found, update the report status and details
                    report.resource_ids_status[f"{log_group_name} has Metric Filters for Authentication Failures: [{', '.join(matching_filters)}]"] = True
                    any_matching_filter_found = True
                    
            # If no matching filter was found in any log group, set the report as failed
            if not any_matching_filter_found:
                report.passed = False
                report.resource_ids_status["No matching filters found for Authentication Failures in any log group"] = False

        except Exception as e:
            logging.error(f"Error while fetching CloudWatch logs and metric filters: {e}")
            report.passed = False
            report.resource_ids_status = {}

        return report
