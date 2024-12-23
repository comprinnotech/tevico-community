"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
import re
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_unauthorized_api_calls(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        cloudwatch_client = connection.client('logs')

        try:
            log_groups = cloudwatch_client.describe_log_groups()['logGroups']
        except Exception as e:
            report.passed = False
            report.resource_ids_status['CloudWatch:describe_log_groups'] = False
            return report

        pattern = r"\$\.errorCode\s*=\s*.?\*UnauthorizedOperation.+\$\.errorCode\s*=\s*.?AccessDenied\*"

        for log_group in log_groups:
            try:
                log_group_name = log_group['logGroupName']
                filters = cloudwatch_client.describe_metric_filters(logGroupName=log_group_name)['metricFilters']

                filter_found = False
                for log_filter in filters:
                    try:
                        filter_name = log_filter['filterName']
                        filter_pattern = log_filter.get('filterPattern', '')

                        if re.search(pattern, filter_pattern):
                            report.resource_ids_status[log_group_name + ':' + filter_name] = True
                            filter_found = True
                        else:
                            report.resource_ids_status[log_group_name + ':' + filter_name] = False
                            report.passed = False

                    except Exception as e:
                        report.resource_ids_status[log_group_name]= False
                        report.passed = False
                        continue

                if not filter_found:
                    try:
                        filter_name = 'UnauthorizedAPICalls'
                        filter_pattern = pattern
                        metric_name = 'UnauthorizedAPICallCount'
                        namespace = 'Custom'

                        cloudwatch_client.put_metric_filter(
                            logGroupName=log_group_name,
                            filterName=filter_name,
                            filterPattern=filter_pattern,
                            metricTransformations=[{
                                'metricName': metric_name,
                                'metricNamespace': namespace,
                                'metricValue': '1'
                            }]
                        )
                        report.resource_ids_status[log_group_name] = True

                    except Exception as e:
                        report.resource_ids_status[log_group_name] = False
                        report.passed = False

            except Exception as e:
                report.resource_ids_status[log_group_name] = False
                report.passed = False
                continue

        return report


