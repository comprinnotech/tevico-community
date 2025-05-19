#!/usr/bin/env python

import argparse
import json
import os
from typing import Any, Dict, List

import yaml

war_reliability_checks = [
    'apigateway_restapi_logging_enabled',
    'apigatewayv2_api_access_logging_enabled',
    'awslambda_function_invoke_api_operations_cloudtrail_logging_enabled',
    'cloudformation_stacks_termination_protection_enabled',
    'cloudtrail_cloudwatch_logging_enabled',
    'dynamodb_tables_pitr_enabled',
    'elb_logging_enabled',
    'opensearch_service_domains_audit_logging_enabled',
    'opensearch_service_domains_cloudwatch_logging_enabled',
    'rds_instance_backup_enabled',
    'rds_instance_deletion_protection',
    'rds_instance_enhanced_monitoring_enabled',
    'rds_instance_integration_cloudwatch_logs',
    'rds_instance_multi_az'
]

def fetch_metadata_files(dir) -> List[str]:
    metadata_files = []
    
    for root, _, files in os.walk(dir):
        for file in files:
            if file.endswith('metadata.json'):
                metadata_files.append(os.path.join(root, file))

    return metadata_files


def read_metadata_file(path: str) -> Dict[str, Any] | None:    
    with open(path, 'r') as json_metadata:
        return json.load(json_metadata)


def main(args: argparse.Namespace):
    dir = args.dir
    
    metadata_files = fetch_metadata_files(dir)
    metadata = []
    
    for file in metadata_files:
        m_data = read_metadata_file(file)
        if m_data is not None and m_data['CheckID'] in war_reliability_checks:
            file_path = f'../library/aws/checks/{m_data['ServiceName']}/{m_data['CheckID']}.yaml'
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w+') as m_data_file:
                yaml.dump(m_data, m_data_file, default_flow_style=False, sort_keys=False, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--dir', dest='dir')
    
    args = parser.parse_args()
    
    main(args)
