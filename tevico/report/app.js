document.addEventListener('DOMContentLoaded', function () {
    updateUI(check_reports, check_analytics);
    setActiveNavLink();
    if (window.updateNavbarAccountInfo) {
        window.updateNavbarAccountInfo(account_id, account_name);
    }
});

updateUI = (reportsData, analyticsData) => {
    try {
        if (!analyticsData?.check_status) {
            throw new Error('Invalid data structure');
        }

        const { check_status, by_severities = [], by_services = [], by_sections = [] } = analyticsData;

        updateSummaryMetrics(reportsData, check_status);

        updatePercentageSubtitles(check_status);

        updateCriticalChecksInfo(by_severities, check_status);

        updateServiceImpactInfo(by_services);

        updateAreaOfFocusInfo(by_sections);

        createDynamicTable({ reportsData, status: 'passed', limit: 5, containerId: 'passedChecksTableContainer' });
        createDynamicTable({ reportsData, status: 'failed', limit: 5, containerId: 'failedChecksTableContainer' });

    } catch (error) {
        console.error('Error updating UI:', error);
    }
}

updateSummaryMetrics = (reportsData, check_status) => {
    const elements = {
        total_checks: check_status.total,
        passed_checks: check_status.passed,
        failed_checks: check_status.failed,
        severity_score: calculateSeverityScore(reportsData)
    };

    updateElements(elements);

    addTotalCountToElement('passed_checks', check_status.total);
    addTotalCountToElement('failed_checks', check_status.total);
}

calculateSeverityScore = (reportsData) => {
    const scores = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
    };

    const statusScores = {
        passed: 0,
        failed: 1,
        skipped: 0,
        not_applicable: 0,
        unknown: 0,
        errored: 0
    }

    const totalScore = reportsData.reduce((acc, check) => acc += ((scores[check.check_metadata.severity] * statusScores[check.status]) || 0), 0);

    const maxPossibleScore = 4;
    const normalizedScore = (totalScore / reportsData.length) / maxPossibleScore;

    return `${(normalizedScore * 100).toFixed(2)}%`;
}

updatePercentageSubtitles = (check_status) => {
    const subtitle = {
        passed: `${((check_status.passed / check_status.total) * 100).toFixed(2)}%`,
        failed: `${((check_status.failed / check_status.total) * 100).toFixed(2)}%`
    };

    for (const [id, value] of Object.entries(subtitle)) {
        updateElementText(id, `i.e. ${value} checks ${id}`);
    }
}

updateCriticalChecksInfo = (by_severities, check_status) => {
    const criticalChecksFailing = by_severities.find(ele => ele.name === 'critical')?.check_status.failed || 0;

    const criticalChecksElement = document.getElementById('critical_checks_failing');
    if (criticalChecksElement) {
        criticalChecksElement.innerHTML = `${criticalChecksFailing}<span class="text-muted fs-5 fw-normal">/${check_status.failed}</span>`;
    } else {
        console.warn('Element with ID "critical_checks_failing" not found');
    }

    const criticalChecksFailingPer = (criticalChecksFailing / check_status.failed) * 100 || 0;
    updateElementText('critical_checks_failing_subheading', `i.e. ${criticalChecksFailingPer.toFixed(2)}%`);
}

updateServiceImpactInfo = (by_services) => {
    const majorImpactService = findMajorImpactService(by_services);

    const impactedServiceNameElement = document.getElementById('impacted_service_name');
    if (impactedServiceNameElement) {
        impactedServiceNameElement.innerText = majorImpactService.name;
        impactedServiceNameElement.href = `./browse.html?status=failed&service=${encodeURIComponent(majorImpactService.name)}`;
    } else {
        console.warn('Element with ID "impacted_service_name" not found');
    }

    updateElementText('impacted_service_count', `with ${majorImpactService.check_status.failed} failed checks`);
}

findMajorImpactService = (by_services) => {
    return by_services.reduce((acc, item) => {
        const currFailed = item.check_status.failed || 0;
        if (!acc.check_status?.failed || (currFailed && currFailed > acc.check_status.failed)) {
            return Object.assign({}, item);
        }
        return acc;
    }, {});
}

updateAreaOfFocusInfo = (by_sections) => {

    const [areaOfFocus] = [...by_sections].sort((a, b) => b.check_status.failed - a.check_status.failed);

    const areaOfFocusElement = document.getElementById('area_of_focus');
    if (areaOfFocusElement) {
        areaOfFocusElement.innerText = areaOfFocus.name;
        areaOfFocusElement.href = `./browse.html?status=failed&section=${encodeURIComponent(areaOfFocus.name)}`;
    } else {
        console.warn('Element with ID "area_of_focus" not found');
    }

    updateElementText('area_of_focus_count', `with ${areaOfFocus.check_status.failed} failed checks`);
}

updateElements = (elements) => {
    for (const [id, value] of Object.entries(elements)) {
        updateElementText(id, String(value || 0));
    }
}

updateElementText = (id, text) => {
    const element = document.getElementById(id);
    if (element) {
        element.innerText = text;
    } else {
        console.warn(`Element with ID "${id}" not found`);
    }
}

addTotalCountToElement = (id, total) => {
    const element = document.getElementById(id);
    if (element) {
        element.innerHTML = `${element.innerText}<span class="text-muted fs-5 fw-normal">/${total}</span>`;
    }
}

createDynamicTable = ({ reportsData, status, limit, containerId }) => {
    const criticalFailingChecks = reportsData.filter(d => d.check_metadata.severity === 'critical' && (d.status === status)).slice(0, limit);
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