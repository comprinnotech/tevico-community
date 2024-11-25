let currentPage = 1;
let list;

function updatePaginationInfo() {
    const totalItems = list.matchingItems.length;
    const pageSize = list.page;
    const startIndex = (currentPage - 1) * pageSize + 1;
    const endIndex = Math.min(startIndex + pageSize - 1, totalItems);

    const paginationInfo = document.querySelector('.pagination-info');
    if (paginationInfo) {
        if (totalItems === 0) {
            paginationInfo.textContent = 'No entries found';
        } else if (startIndex > endIndex) {
            paginationInfo.textContent = 'No entries found';
        } else if (startIndex === endIndex) {
            paginationInfo.textContent = `Showing ${startIndex} of ${totalItems}`;
        } else {
            paginationInfo.textContent = `Showing ${startIndex}-${endIndex} of ${totalItems}`;
        }
    }

}

function updatePaginationButtons() {
    const totalItems = list.matchingItems.length;
    const pageSize = list.page;
    const totalPages = Math.ceil(totalItems / pageSize);

    const isFirstPage = currentPage === 1;
    const isLastPage = currentPage === totalPages;

    const prevBtn = document.querySelector('.pagination .prev');
    const nextBtn = document.querySelector('.pagination .next');

    if (prevBtn) prevBtn.classList.toggle('disabled', isFirstPage);
    if (nextBtn) nextBtn.classList.toggle('disabled', isLastPage);

    document.querySelectorAll('.pagination li:not(.prev):not(.next)').forEach((item, index) => {
        item.classList.toggle('active', index + 1 === currentPage);
    });
}

function initializeListJS() {
    const options = {
        sortClass: 'table-sort',
        listClass: 'table-tbody',
        searchClass: 'table-search',
        valueNames: ['sort-check_metadata.check_title', 'sort-check_metadata.severity', 'sort-check_metadata.service_name', 'sort-section', 'sort-status'],
        page: 15,
        pagination: true
    };

    list = new List('table-default', options);

    list.on('updated', () => {
        updatePaginationInfo();
        updatePaginationButtons();
    });

    const paginationContainer = document.querySelector('.pagination');
    if (paginationContainer) {
        paginationContainer.addEventListener('click', handlePaginationClick);
    }
    updatePaginationInfo();
    updatePaginationButtons();
}

function handlePaginationClick(e) {
    const target = e.target.closest('a');
    if (!target) return;

    e.preventDefault();

    if (target.parentElement.classList.contains('prev')) {
        if (currentPage > 1) currentPage--;
    } else if (target.parentElement.classList.contains('next')) {
        if (currentPage < Math.ceil(list.matchingItems.length / list.page)) currentPage++;
    } else {
        currentPage = parseInt(target.textContent, 10);
    }

    updatePaginationInfo();
    updatePaginationButtons();
}

document.addEventListener('DOMContentLoaded', function () {
    createDynamicTable({ reportsData: check_reports });
});

function createDynamicTable({ reportsData }) {
    const headersArray = [
        { label: '#', key: '#' },
        { label: 'check', key: 'check_metadata.check_title' },
        { label: 'severity', key: 'check_metadata.severity' },
        { label: 'service', key: 'check_metadata.service_name' },
        { label: 'section', key: 'section' },
        { label: 'status', key: 'status' },
        { label: 'action', key: 'action' }
    ];

    const table = document.createElement('table');
    table.className = 'table table-vcenter';

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    headersArray.forEach(header => {
        const th = document.createElement('th');
        if (header.key !== 'action' && header.key !== '') {
            const button = document.createElement('button');
            button.className = 'table-sort';
            button.setAttribute('data-sort', `sort-${header.key}`);
            button.textContent = header.label;
            th.appendChild(button);
        } else {
            th.textContent = header.label;
        }
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    tbody.className = 'table-tbody';
    reportsData.forEach((item, i) => {
        const row = document.createElement('tr');
        headersArray.forEach(header => {
            const td = document.createElement('td');

            switch (header.key) {
                case 'action':
                    const link = document.createElement('a');
                    link.href = `check-details.html?id=${item.name}`;
                    link.className = 'btn btn-primary btn-sm';
                    link.textContent = 'View Details';
                    td.appendChild(link);
                    break;
                case 'status':
                    td.className = `sort-${header.key}`;
                    td.textContent = item.passed ? 'Passed' : 'Failed';
                    break;
                case '#':
                    td.textContent = i + 1;
                    break;
                default:
                    td.className = `sort-${header.key}`;
                    td.textContent = header.key.split('.').reduce((obj, key) => obj && obj[key], item) || '';
            }
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });
    table.appendChild(tbody);

    const container = document.getElementById("tableContainer");
    container.innerHTML = '';
    container.appendChild(table);
    initializeListJS();
    initializeDropdowns(reportsData)
}

createDropdownItem = (text, dropdownId, filterType) => {
    const item = document.createElement('a');
    item.className = 'dropdown-item';
    item.href = '#';
    item.textContent = text;

    item.addEventListener('click', (e) => {
        e.preventDefault();
        const dropdownButton = document.querySelector(`#${dropdownId}`).closest('.dropdown').querySelector('.dropdown-toggle');

        if (dropdownButton) {
            if (dropdownButton.textContent === text) {
                dropdownButton.textContent = getDefaultTextForDropdown(dropdownId);
                activeFilters[filterType] = null;
            } else {
                dropdownButton.textContent = text;
                activeFilters[filterType] = text;
            }
        }
        applyFilters();
    });

    return item;
}

function applyFilters() {
    list.filter();

    list.filter(item => {
        const sectionMatch = !activeFilters.section ||
            item.values()['sort-section'] === activeFilters.section;

        const serviceMatch = !activeFilters.service ||
            item.values()['sort-check_metadata.service_name'] === activeFilters.service;

        const severityMatch = !activeFilters.severity ||
            item.values()['sort-check_metadata.severity'] === activeFilters.severity;

        return sectionMatch && serviceMatch && severityMatch;
    });
}

populateDropdown = (data, dropdownId, valueAccessor, filterType) => {
    const uniqueValues = data.reduce((acc, item) => {
        const value = valueAccessor(item);
        if (value && !acc.includes(value)) {
            acc.push(value);
        }
        return acc;
    }, []).sort((a, b) => a.localeCompare(b));

    const dropdownMenu = document.getElementById(dropdownId);
    dropdownMenu.innerHTML = '';

    uniqueValues.forEach(value => {
        dropdownMenu.appendChild(createDropdownItem(value, dropdownId, filterType));
    });

    return uniqueValues;
}

getDefaultTextForDropdown = (dropdownId) => {
    const defaults = {
        'sectionDropdown': 'Select Section',
        'serviceDropdown': 'Select Service',
        'severityDropdown': 'Select Severity'
    };
    return defaults[dropdownId] || 'Select Option';
}

function initializeDropdowns(reportsData) {
    const dropdownConfigs = [
        {
            id: 'sectionDropdown',
            accessor: item => item.section,
            filterType: 'section'
        },
        {
            id: 'serviceDropdown',
            accessor: item => item.check_metadata?.service_name,
            filterType: 'service'
        },
        {
            id: 'severityDropdown',
            accessor: item => item.check_metadata?.severity,
            filterType: 'severity'
        }
    ];

    activeFilters = {
        section: null,
        service: null,
        severity: null
    };

    dropdownConfigs.forEach(config => {
        populateDropdown(reportsData, config.id, config.accessor, config.filterType);

        const dropdownButton = document.querySelector(`#${config.id}`).closest('.dropdown').querySelector('.dropdown-toggle');
        if (dropdownButton) {
            dropdownButton.textContent = getDefaultTextForDropdown(config.id);
        }
    });
}

function clearAllFilters() {
    Object.keys(activeFilters).forEach(key => {
        activeFilters[key] = null;
    });

    const dropdownIds = ['sectionDropdown', 'serviceDropdown', 'severityDropdown'];
    dropdownIds.forEach(id => {
        const dropdownButton = document.querySelector(`#${id}`).closest('.dropdown').querySelector('.dropdown-toggle');
        if (dropdownButton) {
            dropdownButton.textContent = getDefaultTextForDropdown(id);
        }
    });
    list.filter();
}