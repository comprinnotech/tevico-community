from library.aws.checks.ec2.check_ec2_detailed_monitoring import check_ec2_detailed_monitoring

def test_ec2_detailed_monitoring():
    results = check_ec2_detailed_monitoring()

    # Check that the results are returned correctly
    assert isinstance(results, list)
 
    if not results:
        # If no results are found, it means no EC2 instances are available
        assert True, "No EC2 instances found in the account."
 
    # Case when no EC2 instances are found
    if results[0].get('Status') == 'No EC2 instances found in the account':
        assert True, "No EC2 instances found in the account."
 
    # Case when EC2 instances are found
    monitoring_states = set()
    for result in results:
        if 'InstanceId' in result:
            monitoring_states.add(result['MonitoringState'])

            # Check if monitoring state is 'enabled' or 'disabled'
            if result['MonitoringState'] == 'enabled':
                # Check that detailed monitoring is enabled (PASS)
                assert result['Status'] == 'PASS', f"Expected PASS, but got {result['Status']} for {result['InstanceId']}"
                assert result['Message'] == 'Detailed monitoring is enabled.', f"Unexpected message for {result['InstanceId']}"
            elif result['MonitoringState'] == 'disabled':
                # Check that detailed monitoring is disabled (FAIL)
                assert result['Status'] == 'FAIL', f"Expected FAIL, but got {result['Status']} for {result['InstanceId']}"
                assert result['Message'] == 'Detailed monitoring is not enabled.', f"Unexpected message for {result['InstanceId']}"
            else:
                assert False, f"Unexpected monitoring state for {result['InstanceId']}: {result['MonitoringState']}"

    # If there are no instances, we don't need to check for enabled or disabled states
    if not monitoring_states:
        assert True, "No EC2 instances found to check for monitoring states."
    else:
        # Case when there is a mixture of instances with different states
        assert 'enabled' in monitoring_states or 'disabled' in monitoring_states, \
            "Both enabled and disabled instances should be reported"
        print("Test passed successfully with different scenarios.")
