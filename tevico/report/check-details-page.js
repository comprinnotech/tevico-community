
document.addEventListener('DOMContentLoaded', function () {
    if (window.updateNavbarAccountInfo) {
        window.updateNavbarAccountInfo(account_id, account_name);
    }

    const source = getQueryParam('from');
    const id = getQueryParam('id');

    const backArrow = document.getElementById('backButton');
    const firstBreadcrumb = document.querySelector('.breadcrumb-item:first-child');

    const navigationMap = {
        'browse': {
            href: './browse.html',
            text: 'Browse Checks'
        },
        'war': {
            href: './well-architected-review.html',
            text: 'Well-Architected Review'
        }
    };

    if (id) {
        setActiveNavLink();
        const report = check_reports.find(item => item.name === id);
        if (report) {
            displayCheckDetails(report);
            if (source && navigationMap[source]) {
                const { href, text } = navigationMap[source];
                const sectionParam = source === 'war' && report.section ? `?section=${report.section}` : '';
                backArrow.href = `${href}${sectionParam}`;
                firstBreadcrumb.innerHTML = `<a href="${href}${sectionParam}">${text}</a>`;
            }
        } else {
            console.error('Report not found for ID:', id);
        }
    } else {
        console.error('No ID parameter provided in URL');
        window.location.href = 'index.html';
    }
});

function displayCheckDetails(report) {
    const { check_metadata: meta = {}, resource_ids_status, status } = report;

    updateMetadataElements({ meta, report, status });

    if (Object.entries(resource_ids_status).length) {
        createResourceStatusTable(resource_ids_status);
    }
}

function updateMetadataElements({ meta, report, status }) {
    const updateElement = (id, value) => {
        const element = document.getElementById(id);
        if (element && id !== "status_text") {
            element.textContent = value || '-';
        }
        if (element && id === "status_text") {
            switch (value) {
                case 'passed':
                    element.innerHTML = `<span class="badge bg-softer-success">Passed</span>`;
                    break;
                case 'failed':
                    element.innerHTML = `<span class="badge bg-softer-danger">Failed</span>`;
                    break;
                case 'skipped':
                    element.innerHTML = `<span class="badge bg-soft-info">Skipped</span>`;
                    break;
                case 'not_applicable':
                    element.innerHTML = `<span class="badge bg-soft-info">Not Applicable</span>`;
                    break;
                case 'unknown':
                    element.innerHTML = `<span class="badge bg-softer-warning">Unknown</span>`;
                    break;
                case 'errored':
                    element.innerHTML = `<span class="badge bg-soft-danger">Errored</span>`;
                    break;
                default:
                    element.textContent = '-';
            }
        }
    };

    const updates = [
        { elementId: 'page_title', value: meta.check_id },
        { elementId: 'framework_text', value: report.framework },
        { elementId: 'check_title_text', value: meta.check_title },
        { elementId: 'check_id_text', value: meta.check_id },
        { elementId: 'description_text', value: meta.description },
        { elementId: 'resource_id_template_text', value: meta.resource_id_template },
        { elementId: 'resource_type_text', value: meta.resource_type },
        { elementId: 'risk_text', value: meta.risk },
        { elementId: 'service_name_text', value: meta.service_name },
        { elementId: 'severity_text', value: meta.severity },
        { elementId: 'status_text', value: status }
    ];

    updates.forEach(({ elementId, value }) => updateElement(elementId, value));
}

function createResourceStatusTable(resource_ids_status) {
    const headers = [
        { label: '#', key: '#' },
        { label: 'Resource ARN', key: 'resource' },
        { label: 'Details', key: 'summary' },
        { label: 'Status', key: 'status' }
    ];

    const table = createTableStructure(headers);
    const tbody = createTableBody(resource_ids_status, headers);
    table.appendChild(tbody);

    const container = document.getElementById("tableContainer");
    container.innerHTML = '';
    container.appendChild(wrapInCard(table));
}

function createTableStructure(headers) {
    const table = document.createElement('table');
    table.className = 'table table-vcenter';

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    headers.forEach(header => {
        const th = document.createElement('th');
        th.textContent = header.label;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);
    return table;
}

function createTableBody(resource_ids_status, headers) {
    const tbody = document.createElement('tbody');
    tbody.className = 'table-tbody';

    resource_ids_status.forEach((item, index) => {
        const { exception = "", resource: { arn, name }, status, summary = "" } = item;
        const row = document.createElement('tr');

        headers.forEach(header => {
            const td = document.createElement('td');
            td.innerHTML = getCellContent(header.key, { resource: arn || name || '-', status, index, summary, exception: exception || '' });
            td.style.minWidth = '40%';
            td.style.textWrap = 'wrap';

            if (header.key === '#') {
                td.className = 'row-index';
                td.style.width = '15px';
                td.style.minWidth = '15px';
            }

            if (header.key === 'status') {
                td.style.width = '10%';
            }

            row.appendChild(td);
        });

        tbody.appendChild(row);
    });

    return tbody;
}

function getCellContent(key, { resource, status, index, summary, exception }) {
    switch (key) {
        case 'status':
            return formatStatus(status);
        case '#':
            return index + 1;
        case 'resource':
            return resource;
        case 'summary':
            return exception ? `
                <p style="margin-bottom: 0">${summary}</p>
                <p style="margin-bottom: 0; margin-top: 1rem;">${exception}</p>
            ` : '<p style="margin-bottom: 0">' + summary + '</p>';
        default:
            return '';
    }
}

function formatStatus(status) {
    switch (status) {
        case 'passed':
            return `<span class="badge bg-softer-success">Passed</span>`;
        case 'failed':
            return `<span class="badge bg-softer-danger">Failed</span>`;
        case 'skipped':
            return `<span class="badge bg-soft-info">Skipped</span>`;
        case 'not_applicable':
            return `<span class="badge bg-soft-info">Not Applicable</span>`;
        case 'unknown':
            return `<span class="badge bg-softer-warning">Unknown</span>`;
        case 'errored':
            return `<span class="badge bg-soft-danger">Errored</span>`;
        default:
            return `<span>-</span>`;
    }
}


function wrapInCard(element) {
    const card = document.createElement('div');
    card.classList.add('card');

    const cardBody = document.createElement('div');
    cardBody.classList.add('card-body', 'px-0');

    cardBody.appendChild(element);
    card.appendChild(cardBody);

    return card;
}