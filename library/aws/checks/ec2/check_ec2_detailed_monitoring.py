import boto3

def check_ec2_detailed_monitoring():
    ec2 = boto3.client('ec2')
    instances = ec2.describe_instances()
    print(instances)  # Debugging line to check the response
    results = []

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            monitoring_state = instance.get('Monitoring', {}).get('State', 'disabled')
            if monitoring_state != 'enabled':
                results.append({
                    'InstanceId': instance_id,
                    'MonitoringState': monitoring_state,
                    'Status': 'FAIL',
                    'Message': 'Detailed monitoring is not enabled.'
                })
            else:
                results.append({
                    'InstanceId': instance_id,
                    'MonitoringState': monitoring_state,
                    'Status': 'PASS',
                    'Message': 'Detailed monitoring is enabled.'
                })
    if not results:
        results.append({
            'Status': 'No EC2 instances found in the account'
        })
    return results
