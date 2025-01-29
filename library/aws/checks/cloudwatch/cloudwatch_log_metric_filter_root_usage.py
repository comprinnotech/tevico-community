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


class cloudwatch_log_metric_filter_root_usage(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize CloudWatch client
        client = connection.client('logs')
        cloudwatch = connection.client('cloudwatch')
        report = CheckReport(name=__name__)
        
        # Initialize report status as 'Passed' unless no filter/alarm is found
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        # Define the custom pattern for root account usage
        pattern = r"\$\.userIdentity\.type\s*=\s*.?Root.+\$\.userIdentity\.invokedBy NOT EXISTS.+\$\.eventType\s*!=\s*.?AwsServiceEvent.?"

        try:
            # Fetch all log groups
            log_groups = []
            next_token = None

            while True:
                response = client.describe_log_groups(nextToken=next_token) if next_token else client.describe_log_groups()
                log_groups.extend(response.get('logGroups', []))
                next_token = response.get('nextToken', None)
                if not next_token:
                    break

            # Check for metric filters and alarms in each log group
            for log_group in log_groups:
                log_group_name = log_group['logGroupName']

                # Check for metric filters
                filters_response = client.describe_metric_filters(logGroupName=log_group_name)
                filters = filters_response.get('metricFilters', [])

                filter_found = False
                filter_name = None
                for metric_filter in filters:
                    if re.search(pattern, metric_filter.get('filterPattern', '')):
                        filter_found = True
                        filter_name = metric_filter['filterName']
                        print(filter_name)
                        break

                # If a filter is found, check for associated alarms
                if filter_found:
                    alarm_found = False
                    alarm_name = None

                    alarms_response = cloudwatch.describe_alarms(AlarmNamePrefix=filter_name)
                    alarms = alarms_response.get('MetricAlarms', [])
                    for alarm in alarms:
                        if alarm.get('AlarmName', '').startswith(filter_name):
                            alarm_found = True
                            alarm_name = alarm['AlarmName']
                            break

                    if alarm_found:
                        # Log group has the required filter and alarm
                        report.resource_ids_status[
                            f"{log_group_name} (Filter: {filter_name}, Alarm: {alarm_name})"
                        ] = True
                    else:
                        # Filter exists but no alarm is found
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[
                            f"{log_group_name} (Filter: {filter_name}, No Alarm Found)"
                        ] = False
                else:
                    # No filter found for the log group
                    report.status = ResourceStatus.FAILED

            # If no log groups have filters and alarms, mark the report as failed
            if not any(report.resource_ids_status.values()):
                report.status = ResourceStatus.FAILED
                report.resource_ids_status["No log group with the required filter and alarm found"] = False

        except Exception as e:
            logging.error(f"Error while checking log metric filters and alarms: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
