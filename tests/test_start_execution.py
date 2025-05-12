from typing import List
import pytest
from unittest.mock import patch

from library.aws.provider import AWSProvider
from tevico.engine.entities.provider.provider import CheckReport, CheckStatus
from tevico.engine.configs.config import TevicoConfig


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









# Add a pytest fixture to mock ConfigUtils.get_config globally
@pytest.fixture(autouse=True)
def mock_config_utils_get_config():
    with patch('tevico.engine.configs.config.ConfigUtils.get_config', return_value=TevicoConfig(thread_workers=4)) as mock:
        yield mock


# This will be called during test collection to inject parameters
def pytest_generate_tests(metafunc):
    if "report" in metafunc.fixturenames:
        try:
            provider = AWSProvider()
            reports = provider.start_execution()
            print(f"Fetched {len(reports)} check reports.")
        except Exception as e:
            print(f"Failed to get check reports: {e}")
            reports = []

        metafunc.parametrize("report", reports)











def test_check_report(report: CheckReport):
    """Tests the check report to ensure consistency of resource IDs status.

    Args:
        report (CheckReport): The check report to be tested.
    """
    # If resource_ids_status is empty, skip the assertion as the passed status
    # could be either PASSED or UNKNOWN based on other factors
    if not report.resource_ids_status:
        assert report.status in [CheckStatus.PASSED, CheckStatus.UNKNOWN]
        return

    # For non-empty resource_ids_status, perform the regular checks
    failed_statuses = {CheckStatus.FAILED, CheckStatus.ERRORED, CheckStatus.UNKNOWN}
    if any(resource.status in failed_statuses for resource in report.resource_ids_status):
        assert report.status == CheckStatus.FAILED
    else:
        assert report.status == CheckStatus.PASSED
