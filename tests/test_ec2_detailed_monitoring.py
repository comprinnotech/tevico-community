import boto3
import pytest
from botocore.stub import Stubber
from types import SimpleNamespace
from typing import cast

# Import the module and components under test
import library.aws.checks.ec2.check_ec2_detailed_monitoring as mod
from library.aws.checks.ec2.check_ec2_detailed_monitoring import check_ec2_detailed_monitoring
from tevico.engine.entities.report.check_model import CheckStatus, CheckMetadata

# Fixtures and Helpers


@pytest.fixture(autouse=True)
def stub_out_checkreport(monkeypatch):
    """
    Automatically replaces the real CheckReport used by the check with a dummy version
    so that we can inspect values like `status`, `summary`, and `resource_ids_status`
    during tests without relying on full CheckReport implementation.
    """
    class DummyReport:
        def __init__(self, name, check_metadata):
            self.name = name
            self.check_metadata = check_metadata
            self.resource_ids_status = []
            self.status = None

    monkeypatch.setattr(mod, 'CheckReport', DummyReport)


@pytest.fixture
def boto_session():
    """
    Returns a boto3 Session object preconfigured with the 'us-east-1' region.
    All EC2 clients used in tests will derive from this session.
    """
    return boto3.Session(region_name='us-east-1')


def make_describe_instances_response(instances_list):
    """
    Given a list of EC2 instance dictionaries, wraps them in the format expected
    by the EC2 `describe_instances` API response.
    """
    reservations = []
    if instances_list:
        reservations = [{
            'Instances': [inst.copy() for inst in instances_list]
        }]
    return {'Reservations': reservations}


def make_check():
    """
    Constructs an instance of the EC2 detailed monitoring check
    and injects dummy metadata (as required by the framework).
    """
    chk = check_ec2_detailed_monitoring()
    chk.metadata = cast(CheckMetadata, SimpleNamespace(name='ec2_detailed_monitoring'))
    return chk


def prepare_stubbed_ec2(session, responses=None, client_error=None):
    """
    Creates a stubbed EC2 client from the session:
    - If `responses` is passed, they are added as fake responses.
    - If `client_error` is passed, it simulates an API failure.
    - Monkey-patches `session.client()` to always return this stub.
    """
    real_ec2 = session.client('ec2')
    stub = Stubber(real_ec2)

    if responses:
        for operation, response in responses:
            stub.add_response(operation, response)
    if client_error:
        op, code, msg = client_error
        stub.add_client_error(op, service_error_code=code, service_message=msg)

    stub.activate()
    session.client = lambda service_name, **kwargs: real_ec2
    return stub


# Test Cases

def test_no_instances(boto_session):
    """
    Test case when no EC2 instances are returned by describe_instances.
    Should mark the check as NOT_APPLICABLE.
    """
    stub = prepare_stubbed_ec2(
        boto_session,
        responses=[('describe_instances', make_describe_instances_response([]))]
    )

    chk = make_check()
    report = chk.execute(connection=boto_session)

    stub.deactivate()

    assert len(report.resource_ids_status) == 1
    rs = report.resource_ids_status[0]
    assert rs.status == CheckStatus.NOT_APPLICABLE
    assert "No EC2 instances found" in (rs.summary or "")


def test_instance_enabled(boto_session):
    """
    Test case where the EC2 instance has detailed monitoring ENABLED.
    The check should PASS and the summary message should confirm it.
    """
    inst = {
        'InstanceId': 'i-0123456789abcdef0',
        'State': {'Name': 'running'},
        'Monitoring': {'State': 'enabled'}
    }
    stub = prepare_stubbed_ec2(
        boto_session,
        responses=[('describe_instances', make_describe_instances_response([inst]))]
    )

    chk = make_check()
    report = chk.execute(connection=boto_session)

    stub.deactivate()

    # Collect results keyed by instance ID (gracefully ignoring type warnings)
    statuses = {getattr(r.resource, 'name', None): r for r in report.resource_ids_status}  # type: ignore[index]
    rs = statuses['i-0123456789abcdef0']
    assert rs.status == CheckStatus.PASSED
    assert rs.summary == "Detailed monitoring enabled for i-0123456789abcdef0."


def test_instance_disabled(boto_session):
    """
    Test case where the EC2 instance has detailed monitoring DISABLED.
    The check should FAIL and the summary message should reflect it.
    """
    inst = {
        'InstanceId': 'i-0fedcba9876543210',
        'State': {'Name': 'running'},
        'Monitoring': {'State': 'disabled'}
    }
    stub = prepare_stubbed_ec2(
        boto_session,
        responses=[('describe_instances', make_describe_instances_response([inst]))]
    )

    chk = make_check()
    report = chk.execute(connection=boto_session)

    stub.deactivate()

    statuses = {getattr(r.resource, 'name', None): r for r in report.resource_ids_status}  # type: ignore[index]
    rs = statuses['i-0fedcba9876543210']
    assert rs.status == CheckStatus.FAILED
    assert rs.summary == "Detailed monitoring NOT enabled for i-0fedcba9876543210."


def test_ec2_error_handling(boto_session):
    """
    Test case where the EC2 `describe_instances` call throws an InternalError.
    The check should return UNKNOWN status and capture the error message.
    """
    stub = prepare_stubbed_ec2(
        boto_session,
        client_error=('describe_instances', 'InternalError', 'Something went wrong')
    )

    chk = make_check()
    report = chk.execute(connection=boto_session)

    stub.deactivate()

    assert report.status == CheckStatus.UNKNOWN
    assert len(report.resource_ids_status) == 1
    rs = report.resource_ids_status[0]
    assert rs.status == CheckStatus.UNKNOWN
    assert "Error retrieving EC2 monitoring status" in (rs.summary or "")
    assert "Something went wrong" in (rs.exception or "")
