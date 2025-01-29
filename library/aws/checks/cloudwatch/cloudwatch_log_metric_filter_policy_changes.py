"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-13
"""

import boto3
import logging
import re

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_policy_changes(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize CloudWatch client
        client = connection.client('logs')
        
        report = CheckReport(name=__name__)
        
        # Initialize report status as 'Passed' unless we find a missing filter
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Define the custom pattern for IAM policy changes (Put/Attach/Delete actions)
        pattern = r"\$\.eventName\s*=\s*.?DeleteGroupPolicy.+\$\.eventName\s*=\s*.?DeleteRolePolicy.+\$\.eventName\s*=\s*.?DeleteUserPolicy.+\$\.eventName\s*=\s*.?PutGroupPolicy.+\$\.eventName\s*=\s*.?PutRolePolicy.+\$\.eventName\s*=\s*.?PutUserPolicy.+\$\.eventName\s*=\s*.?CreatePolicy.+\$\.eventName\s*=\s*.?DeletePolicy.+\$\.eventName\s*=\s*.?CreatePolicyVersion.+\$\.eventName\s*=\s*.?DeletePolicyVersion.+\$\.eventName\s*=\s*.?AttachRolePolicy.+\$\.eventName\s*=\s*.?DetachRolePolicy.+\$\.eventName\s*=\s*.?AttachUserPolicy.+\$\.eventName\s*=\s*.?DetachUserPolicy.+\$\.eventName\s*=\s*.?AttachGroupPolicy.+\$\.eventName\s*=\s*.?DetachGroupPolicy.?"
        
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

            # Check for Metric Filters for policy changes in each log group
            for log_group in log_groups:
                log_group_name = log_group['logGroupName']
                
                # Fetch metric filters for the log group
                filters = client.describe_metric_filters(logGroupName=log_group_name)
                
                # Look for filters related to IAM policy changes with the custom pattern
                matching_filters = []
                for filter in filters.get('metricFilters', []):
                    filter_pattern = filter.get('filterPattern', '')
                    # Check if the filter pattern matches the custom pattern for policy changes
                    if re.search(pattern, filter_pattern):
                        matching_filters.append(filter.get('filterName'))

                if matching_filters:
                    # If a matching filter is found, update the report status and details
                    report.resource_ids_status[f"{log_group_name} has Metric Filters for Policy Changes: [{', '.join(matching_filters)}]"] = True
                    any_matching_filter_found = True


            # If no matching filter was found in any log group, set the report as failed
            if not any_matching_filter_found:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status["No matching filters found for IAM Policy Changes in any log group"] = False

        except Exception as e:
            logging.error(f"Error while fetching CloudWatch logs and metric filters: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
