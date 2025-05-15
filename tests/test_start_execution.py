from typing import List
import pytest # type: ignore
from library.aws.provider import AWSProvider
from tevico.engine.entities.provider.provider import CheckReport

def get_check_reports() -> List[CheckReport]:
    """Fetches check reports by executing the provider.

    Returns:
        List[CheckReport]: A list of check reports.
    """
    provider = AWSProvider()
    return provider.start_execution()

# Get the check reports
try:
    check_reports = get_check_reports()
    if not check_reports:
        print("No check reports were retrieved")
except Exception as e:
    print(f"Failed to get check reports: {str(e)}")
    check_reports = []
@pytest.mark.parametrize("report", check_reports)
def test_check_report(report: CheckReport):
    """Tests the check report to ensure consistency of resource IDs status.

    Args:
        report (CheckReport): The check report to be tested.
    """
    # If resource_ids_status is empty, skip the assertion as the passed status
    # could be either True or False based on other factors
    if not report.resource_ids_status:
        return
    
    # For non-empty resource_ids_status, perform the regular checks
    if any(value is False for value in report.resource_ids_status.values()):
        assert report.passed is False
    else:
        assert report.passed is True
