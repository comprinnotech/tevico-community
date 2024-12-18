document.addEventListener('DOMContentLoaded', function () {
    updateUI(check_reports, check_analytics);
    setActiveNavLink();
});

function updateUI(reportsData, analyticsData) {

    const reports = reportsData.filter(
        (check) => check.check_metadata.severity === "critical",
    )

    try {
        if (!analyticsData?.check_status) {
            throw new Error('Invalid data structure');
        }

        const { check_status, by_severities = [], by_services = [], by_sections = [] } = analyticsData;

        const elements = {
            total_checks: check_status.total,
            passed_checks: check_status.passed,
            failed_checks: check_status.failed,
            severity_score: `${(((reportsData.reduce((acc, check) => {
                const scores = {
                    critical: 4,
                    high: 3,
                    medium: 2,
                    low: 1,
                };
                return acc + scores[check.check_metadata.severity] || 0;
            }, 0) / reportsData.length) / 4) * 100).toFixed(2)}%`
        };

        const subtitle = {
            passed: `${((check_status.passed / check_status.total) * 100).toFixed(2)}%`,
            failed: `${((check_status.failed / check_status.total) * 100).toFixed(2)}%`
        }

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.innerText = String(value || 0);
            } else {
                console.warn(`Element with ID "${id}" not found`);
            }
        }

        for (const [id, value] of Object.entries(subtitle)) {
            const element = document.getElementById(id);
            if (element) {
                element.innerText = `out of ${check_status.total} i.e. ${value} checks ${id}`;
            } else {
                console.warn(`Element with ID "${id}" not found`);
            }
        }

        const criticalChecksFailing = by_severities.find(ele => ele.name === `critical`)?.check_status.failed;

        const criticalChecksElement = document.getElementById('critical_checks_failing');
        if (criticalChecksElement) {
            criticalChecksElement.innerText = String(criticalChecksFailing || 0);
        } else {
            console.warn(`Element with ID "${id}" not found`);
        }

        const criticalChecksSubElement = document.getElementById('critical_checks_failing_subheading');
        if (criticalChecksSubElement) {
            criticalChecksSubElement.innerText = `out of ${check_status.failed} i.e. ${((criticalChecksFailing / check_status.failed) * 100).toFixed(2)}%`;
        } else {
            console.warn(`Element with ID "${id}" not found`);
        }

        const majorImpactService = by_services.reduce((acc, item) => {
            const currFailed = item.check_status.failed || 0;
            if (acc?.check_status?.failed) {
                if (currFailed && currFailed > acc.check_status.failed) {
                    acc = Object.assign(item);
                }
            } else {
                acc = Object.assign(item);
            }
            return acc;
        }, {})

        const impactedServiceNameElement = document.getElementById('impacted_service_name');
        if (impactedServiceNameElement) {
            impactedServiceNameElement.innerText = `${majorImpactService.name}`;
        } else {
            console.warn(`Element with ID "${id}" not found`);
        }

        const impactedServiceCountElement = document.getElementById('impacted_service_count');
        if (impactedServiceCountElement) {
            impactedServiceCountElement.innerText = `with ${majorImpactService.check_status.failed} failed checks`;
        } else {
            console.warn(`Element with ID "${id}" not found`);
        }

        const [areaOfFocus] = by_sections.sort(
            (a, b) => b.check_status.failed - a.check_status.failed,
        );

        const areaOfFocusElement = document.getElementById('area_of_focus');
        if (areaOfFocusElement) {
            areaOfFocusElement.innerText = `${areaOfFocus.name}`;
        } else {
            console.warn(`Element with ID "${id}" not found`);
        }

        const areaOfFocusCountElement = document.getElementById('area_of_focus_count');
        if (areaOfFocusCountElement) {
            areaOfFocusCountElement.innerText = `with ${areaOfFocus.check_status.failed} failed checks`;
        } else {
            console.warn(`Element with ID "${id}" not found`);
        }

        createDynamicTable({ reportsData, passed: true, limit: 5, containerId: 'passedChecksTableContainer' })
        createDynamicTable({ reportsData, passed: false, limit: 5, containerId: 'failedChecksTableContainer' })

    } catch (error) {
        console.error('Error updating UI:', error);
    }
}

function createDynamicTable({ reportsData, passed, limit, containerId }) {
    const criticalFailingChecks = reportsData.filter(d => d.check_metadata.severity === 'critical' && (d.passed === passed)).slice(0, limit);
    const headersArray = [{ label: 'section', key: 'section' }, { label: 'check', key: 'check_metadata.check_title' }, { label: 'severity', key: 'check_metadata.severity' }, { label: 'service', key: 'check_metadata.service_name' }]

    const table = document.createElement('table');
    table.className = 'table table-vcenter';

    const thead = document.createElement('thead');
    thead.className = 'sticky-top';
    const headerRow = document.createElement('tr');

    headersArray.forEach(header => {
        const th = document.createElement('th');
        th.textContent = header.label;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    criticalFailingChecks.forEach(item => {
        const row = document.createElement('tr');
        headersArray.forEach(header => {
            const td = document.createElement('td');
            td.textContent = header.key.split('.').reduce((obj, key) => obj && obj[key], item) || '';
            if (header.key === 'check_metadata.severity') {
                td.classList.add('text-capitalize');
            }
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });
    table.appendChild(tbody);

    const container = document.getElementById(containerId);
    container.innerHTML = '';
    container.appendChild(table);
}