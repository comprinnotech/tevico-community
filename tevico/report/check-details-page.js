
document.addEventListener('DOMContentLoaded', function () {
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
    const { check_metadata: meta = {}, resource_ids_status } = report;

    updateMetadataElements(meta, report);

    if (Object.entries(resource_ids_status).length) {
        createResourceStatusTable(resource_ids_status);
    }
}

function updateMetadataElements(meta, report) {
    const updateElement = (id, value) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value || '-';
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
        { elementId: 'severity_text', value: meta.severity }
    ];

    updates.forEach(({ elementId, value }) => updateElement(elementId, value));
}

function createResourceStatusTable(resource_ids_status) {
    const headers = [
        { label: '#', key: '#' },
        { label: 'Resource', key: 'resource' },
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

    Object.entries(resource_ids_status).forEach((item, index) => {
        const [resource, status] = item;
        const row = document.createElement('tr');

        headers.forEach(header => {
            const td = document.createElement('td');
            td.innerHTML = getCellContent(header.key, { resource, status, index });

            if (header.key === '#') {
                td.className = 'row-index';
                td.style.width = '15px';
                td.style.minWidth = '15px';
            }

            row.appendChild(td);
        });

        tbody.appendChild(row);
    });

    return tbody;
}

function getCellContent(key, { resource, status, index }) {
    switch (key) {
        case 'status':
            return formatStatus(status);
        case '#':
            return index + 1;
        case 'resource':
            return resource;
        default:
            return '';
    }
}

function formatStatus(status) {
    if (typeof status === 'boolean') {
        const statusValue = status ? 'Passed' : 'Failed';
        const badgeClass = status ? 'bg-softer-success' : 'bg-softer-danger';
        return `<span class="badge ${badgeClass}">${statusValue}</span>`;
    }

    if (typeof status === 'string') {
        const urlPattern = /^(https?:\/\/)/i;
        return urlPattern.test(status)
            ? `<a href="${status}" class="status-link" target="_blank" rel="noopener noreferrer">${status}</a>`
            : `<span class="status-text">${status}</span>`;
    }

    return `<span class="status-text">${String(status)}</span>`;
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