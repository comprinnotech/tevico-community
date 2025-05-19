

from functools import reduce
from typing import Dict, List

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus
from tevico.engine.entities.report.report_model import AnalyticsReport, CheckStatusReport, GeneralReport, SeverityReport


def __check_status_accumulator(acc: CheckStatusReport, check: CheckReport):
    acc.total += 1
    if check.status is CheckStatus.PASSED:
        acc.passed += 1
    elif check.status is CheckStatus.FAILED:
        acc.failed += 1
    elif check.status is CheckStatus.SKIPPED:
        acc.skipped += 1
    elif check.status is CheckStatus.NOT_APPLICABLE:
        acc.not_applicable += 1
    elif check.status is CheckStatus.UNKNOWN:
        acc.unknown += 1
    elif check.status is CheckStatus.ERRORED:
        acc.errored += 1
    return acc

def __severity_accumulator(acc: SeverityReport, check: CheckReport):
    if check.check_metadata is not None:
        if check.check_metadata.severity == 'critical':
            acc.critical += 1
        elif check.check_metadata.severity == 'high':
            acc.high += 1
        elif check.check_metadata.severity == 'medium':
            acc.medium += 1
        elif check.check_metadata.severity == 'low':
            acc.low += 1
    return acc

def __get_sections(checks: List[CheckReport]) -> List[str]:
    sections = set()
    for check in checks:
        if check.check_metadata is not None:
            sections.add(check.section)
    return list(sections)

def __get_services(checks: List[CheckReport]) -> List[str]:
    services = set()
    for check in checks:
        if check.check_metadata is not None:
            services.add(check.check_metadata.service_name)
    return list(services)

def __get_severities(checks: List[CheckReport]) -> List[str]:
    severities = set()
    for check in checks:
        if check.check_metadata is not None:
            severities.add(check.check_metadata.severity)
    return list(severities)

def generate_analytics(checks: List[CheckReport]) -> AnalyticsReport:
    
    # check_status = CheckStatusReport(total=0, passed=0, failed=0)
    severity: SeverityReport = SeverityReport()
    
    by_services: List[GeneralReport] = []
    by_sections: List[GeneralReport] = []
    by_severities: List[GeneralReport] = []
    
    for service in __get_services(checks):
        service_checks = list(filter(lambda check: check.check_metadata is not None and check.check_metadata.service_name == service, checks))
        
        check_status = reduce(__check_status_accumulator, service_checks, CheckStatusReport())
        severity = reduce(__severity_accumulator, service_checks, SeverityReport())
        
        by_services.append(GeneralReport(
            name=service,
            check_status=check_status,
            severity=severity
        ))
        
    for section in __get_sections(checks):
        section_checks = list(filter(lambda check: check.section == section, checks))
        
        check_status = reduce(__check_status_accumulator, section_checks, CheckStatusReport(total=0, passed=0, failed=0))
        severity = reduce(__severity_accumulator, section_checks, SeverityReport())
        
        by_sections.append(GeneralReport(
            name=section,
            check_status=check_status,
            severity=severity
        ))
        
    for severity_str in __get_severities(checks):
        severity_checks = list(filter(lambda check: check.check_metadata is not None and check.check_metadata.severity == severity_str, checks))
        
        check_status = reduce(__check_status_accumulator, severity_checks, CheckStatusReport(total=0, passed=0, failed=0))
        severity = reduce(__severity_accumulator, severity_checks, SeverityReport())
        
        by_severities.append(GeneralReport(
            name=severity_str,
            check_status=check_status,
            severity=severity
        ))
    
    check_status = reduce(__check_status_accumulator, checks, CheckStatusReport(total=0, passed=0, failed=0))
    
    severity = reduce(__severity_accumulator, checks, severity.model_copy())
    
    analytics = AnalyticsReport(
        check_status=check_status,
        severity=severity,
        by_services=by_services,
        by_sections=by_sections,
        by_severities=by_severities
    )
    
    return analytics