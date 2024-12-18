
let currentPage = 1;
let list;
let currentSortColumn = 'sort-check_metadata.check_title';
let currentSortOrder = 'asc';
const activeFilters = {
    section: null,
    service: null,
    severity: null,
    status: null
};

function saveTableState() {
    const state = {
        currentPage,
        currentSortColumn,
        currentSortOrder
    };
    sessionStorage.setItem('tableState', JSON.stringify(state));
}

function loadTableState() {
    const state = sessionStorage.getItem('tableState');
    if (state) {
        const { currentPage: savedPage, currentSortColumn: savedColumn, currentSortOrder: savedOrder } = JSON.parse(state);
        currentPage = savedPage;
        currentSortColumn = savedColumn;
        currentSortOrder = savedOrder;
        return true;
    }
    return false;
}

function clearTableState() {
    sessionStorage.removeItem('tableState');
}

function updatePaginationInfo() {
    const totalItems = list.matchingItems.length;
    const pageSize = list.page;
    const startIndex = (currentPage - 1) * pageSize + 1;
    const endIndex = Math.min(startIndex + (Number(pageSize) - 1), totalItems);

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

    const paginationItems = Array.from(document.querySelectorAll('.pagination li:not(.prev):not(.next)'));

    paginationItems.forEach(item => {
        item.classList.remove('active');
    });

    paginationItems.forEach(item => {
        const pageNum = parseInt(item.textContent, 10);
        if (pageNum === currentPage) {
            item.classList.add('active');
        }
    });
}

function updateRowNumbers() {
    const visibleRows = document.querySelectorAll('.table-tbody tr:not(.hidden):not([style*="display: none"])');
    const itemsPerPage = list.page;
    const startIndex = (currentPage - 1) * itemsPerPage;

    visibleRows.forEach((row, index) => {
        const indexCell = row.querySelector('.row-index');
        if (indexCell) {
            indexCell.textContent = startIndex + index + 1;
        }
    });
}

function initializeListJS() {
    const options = {
        sortClass: 'table-sort',
        listClass: 'table-tbody',
        searchClass: 'table-search',
        valueNames: ['sort-check_metadata.check_title', 'sort-check_metadata.severity', 'sort-check_metadata.service_name', 'sort-section', { name: 'sort-status', attr: 'data-status' }],
        page: 15,
        pagination: true
    };

    list = new List('table-default', options);

    const defaultSortColumn = 'sort-check_metadata.check_title'; // or whatever column you want as default
    const defaultSortOrder = 'asc';

    const referrer = document.referrer;
    if (referrer.includes('check-details.html')) {
        const hasState = loadTableState();
        if (hasState) {
            list.sort(currentSortColumn, { order: currentSortOrder });
            list.show((currentPage - 1) * list.page + 1, list.page);
        } else {
            currentSortColumn = defaultSortColumn;
            currentSortOrder = defaultSortOrder;
            list.sort(currentSortColumn, { order: currentSortOrder });
        }
    } else {
        clearTableState();
        currentSortColumn = defaultSortColumn;
        currentSortOrder = defaultSortOrder;
        list.sort(currentSortColumn, { order: currentSortOrder });
    }

    list.on('sortComplete', function () {
        const sortElements = document.querySelectorAll('.table-sort');
        let sortChanged = false;

        sortElements.forEach(element => {
            if (element.classList.contains('asc')) {
                const newSortColumn = element.getAttribute('data-sort');
                if (currentSortColumn !== newSortColumn || currentSortOrder !== 'asc') {
                    currentSortColumn = newSortColumn;
                    currentSortOrder = 'asc';
                    sortChanged = true;
                }
            } else if (element.classList.contains('desc')) {
                const newSortColumn = element.getAttribute('data-sort');
                if (currentSortColumn !== newSortColumn || currentSortOrder !== 'desc') {
                    currentSortColumn = newSortColumn;
                    currentSortOrder = 'desc';
                    sortChanged = true;
                }
            }
        });

        if (sortChanged) {
            saveTableState();
        }
    });

    function updateSortUI() {
        document.querySelectorAll('.table-sort').forEach(element => {
            const sortColumn = element.getAttribute('data-sort');
            element.classList.remove('asc', 'desc');
            if (sortColumn === currentSortColumn) {
                element.classList.add(currentSortOrder);
            }
        });
    }

    updateSortUI();

    list.on('searchComplete', function () {
        list.sort(currentSortColumn, { order: currentSortOrder });
        updateRowNumbers();
    });

    list.on('filterComplete', function () {
        list.sort(currentSortColumn, { order: currentSortOrder });
        updateRowNumbers();
    });

    list.on('updated', () => {
        updatePaginationInfo();
        updatePaginationButtons();
        updateRowNumbers();
    });

    document.querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', () => {
            setTimeout(() => {
                list.sort(currentSortColumn, { order: currentSortOrder });
                updateRowNumbers();
            }, 0);
        });
    });

    const paginationContainer = document.querySelector('.pagination');
    if (paginationContainer) {
        paginationContainer.addEventListener('click', handlePaginationClick);
    }

    updatePaginationInfo();
    updatePaginationButtons();
    updateRowNumbers();

    return list;
}

function handlePaginationClick(e) {
    const target = e.target.closest('a');
    if (!target) return;

    e.preventDefault();

    const totalPages = Math.ceil(list.matchingItems.length / list.page);

    if (target.parentElement.classList.contains('prev')) {
        if (currentPage > 1) {
            currentPage--;
            list.show((currentPage - 1) * list.page + 1, list.page);
        }
    } else if (target.parentElement.classList.contains('next')) {
        if (currentPage < totalPages) {
            currentPage++;
            list.show((currentPage - 1) * list.page + 1, list.page);
        }
    } else {
        const newPage = parseInt(target.textContent, 10);
        if (!isNaN(newPage) && newPage > 0 && newPage <= totalPages) {
            currentPage = newPage;
            list.show((currentPage - 1) * list.page + 1, list.page);
        }
    }

    saveTableState();
    updatePaginationInfo();
    updatePaginationButtons();
    updateRowNumbers();
}

document.addEventListener('DOMContentLoaded', function () {
    createDynamicTable({ reportsData: check_reports });
    setActiveNavLink();
    const clearButton = document.querySelector('#clearFiltersButton');
    if (clearButton) {
        clearButton.addEventListener('click', clearAllFilters);
    }

    window.addEventListener('beforeunload', function (e) {
        const currentPath = window.location.pathname;
        if (!e.target.activeElement?.href?.includes('check-details.html')) {
            clearTableState();
        }
    });
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
        if (header.key !== 'action' && header.key !== '' && header.key !== '#') {
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
                    link.href = `check-details.html?id=${item.name}&from=browse`;
                    link.className = 'btn btn-primary btn-sm';
                    link.textContent = 'View Details';
                    td.appendChild(link);
                    break;
                case 'check_metadata.severity':
                    td.className = `sort-${header.key}`;
                    td.textContent = header.key.split('.').reduce((obj, key) => obj && obj[key], item) || '';
                    td.classList.add('text-capitalize');
                    break;
                case 'status':
                    td.className = `sort-${header.key}`;
                    const statusValue = item.passed ? 'Passed' : 'Failed';
                    const badgeClass = item.passed ? 'bg-softer-success' : 'bg-softer-danger';
                    td.setAttribute('data-status', statusValue);
                    td.innerHTML = `<span class="badge ${badgeClass}">${statusValue}</span>`;
                    break;
                case '#':
                    td.className = 'row-index';
                    td.textContent = i + 1;
                    break;
                case 'check_metadata.check_title':
                    td.className = `sort-${header.key} text-truncate`;
                    td.style.maxWidth = '250px';
                    td.setAttribute('title', header.key.split('.').reduce((obj, key) => obj && obj[key], item) || '');
                    td.textContent = header.key.split('.').reduce((obj, key) => obj && obj[key], item) || '';
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
    initializeDropdowns(reportsData);
}

const capitalizeText = (text) => text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();

const createDropdownItem = (text, dropdownId, filterType) => {
    const transformedText = filterType === 'severity' ? capitalizeText(text) : text;

    const item = document.createElement('a');
    item.className = 'dropdown-item';
    item.href = '#';
    item.textContent = transformedText;

    item.addEventListener('click', (e) => {
        e.preventDefault();
        const dropdown = document.querySelector(`#${dropdownId}`).closest('.dropdown');
        const dropdownButton = dropdown.querySelector('.dropdown-toggle');
        const allDropdownItems = dropdown.querySelectorAll('.dropdown-item');

        if (dropdownButton) {
            allDropdownItems.forEach(dropItem => {
                dropItem.classList.remove('active');
            });

            if (dropdownButton.textContent === transformedText) {
                dropdownButton.textContent = getDefaultTextForDropdown(dropdownId);
                dropdownButton.classList.remove('active');
                activeFilters[filterType] = null;
            } else {
                dropdownButton.textContent = transformedText;
                dropdownButton.classList.add('active');
                item.classList.add('active');
                activeFilters[filterType] = transformedText;
            }

            applyFilters();
            setTimeout(() => {
                list.sort(currentSortColumn, { order: currentSortOrder });
                updateRowNumbers();
            }, 0);
        }
    });

    if (activeFilters[filterType] === transformedText) {
        item.classList.add('active');
    }

    return item;
}

function applyDefaultFilters() {
    const severity = getQueryParam('severity');
    const status = getQueryParam('status');

    if (severity) {
        const severityDropdown = document.getElementById('severityDropdown');
        const severityItem = Array.from(severityDropdown.querySelectorAll('.dropdown-item'))
            .find(item => item.textContent.toLowerCase() === severity.toLowerCase());
        const dropdownToggle = severityDropdown.closest('.dropdown').querySelector('.dropdown-toggle');

        if (severityItem) {
            activeFilters.severity = severityItem.textContent;
            dropdownToggle.textContent = severityItem.textContent;
            dropdownToggle.classList.add('active');
            severityItem.classList.add('active');
        }
    }

    if (status) {
        const statusDropdown = document.getElementById('statusDropdown');
        const statusItem = Array.from(statusDropdown.querySelectorAll('.dropdown-item'))
            .find(item => item.textContent.toLowerCase() === status.toLowerCase());
        const dropdownToggle = statusDropdown.closest('.dropdown').querySelector('.dropdown-toggle');

        if (statusItem) {
            activeFilters.status = statusItem.textContent;
            dropdownToggle.textContent = statusItem.textContent;
            dropdownToggle.classList.add('active');
            statusItem.classList.add('active');
        }
    }

    if (severity || status) {
        applyFilters();
    }
}

function applyFilters() {
    list.filter(item => {
        const sectionMatch = !activeFilters.section ||
            item.values()['sort-section'] === activeFilters.section;

        const serviceMatch = !activeFilters.service ||
            item.values()['sort-check_metadata.service_name'] === activeFilters.service;

        const severityMatch = !activeFilters.severity ||
            item.values()['sort-check_metadata.severity'] === activeFilters.severity.toLowerCase();

        const statusMatch = !activeFilters.status ||
            item.values()['sort-status'] === activeFilters.status;

        return sectionMatch && serviceMatch && severityMatch && statusMatch;
    });
    setTimeout(() => {
        currentPage = 1;
        list.sort(currentSortColumn, { order: currentSortOrder });
        updateRowNumbers();
    }, 0);
}

const populateDropdown = (data, dropdownId, valueAccessor, filterType) => {
    const dropdownMenu = document.getElementById(dropdownId);
    dropdownMenu.innerHTML = '';

    if (dropdownId === 'statusDropdown') {
        const statusValues = ['Passed', 'Failed'];
        statusValues.forEach(value => {
            dropdownMenu.appendChild(createDropdownItem(value, dropdownId, filterType));
        });
        return statusValues;
    }

    const uniqueValues = data.reduce((acc, item) => {
        const value = valueAccessor(item);
        if (value && !acc.includes(value)) {
            acc.push(value);
        }
        return acc;
    }, []).sort((a, b) => a.localeCompare(b));

    uniqueValues.forEach(value => {
        dropdownMenu.appendChild(createDropdownItem(value, dropdownId, filterType));
    });

    return uniqueValues;
}

const getDefaultTextForDropdown = (dropdownId) => {
    const defaults = {
        'sectionDropdown': 'Select Section',
        'serviceDropdown': 'Select Service',
        'severityDropdown': 'Select Severity',
        'statusDropdown': 'Select Status'
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
        },
        {
            id: 'statusDropdown',
            accessor: item => item.passed ? 'Passed' : 'Failed',
            filterType: 'status'
        }
    ];

    dropdownConfigs.forEach(config => {
        populateDropdown(reportsData, config.id, config.accessor, config.filterType);

        const dropdownButton = document.querySelector(`#${config.id}`).closest('.dropdown').querySelector('.dropdown-toggle');
        if (dropdownButton) {
            dropdownButton.textContent = getDefaultTextForDropdown(config.id);
        }
    });

    applyDefaultFilters();
}

function clearAllFilters() {
    const dropdownIds = ['sectionDropdown', 'serviceDropdown', 'severityDropdown', 'statusDropdown'];

    const hadActiveFilters = Object.values(activeFilters).some(Boolean);

    if (hadActiveFilters) {

        Object.keys(activeFilters).forEach(key => {
            activeFilters[key] = null;
        });

        dropdownIds.forEach(id => {
            const dropdown = document.querySelector(`#${id}`).closest('.dropdown');
            const dropdownButton = dropdown.querySelector('.dropdown-toggle');
            const dropdownItems = dropdown.querySelectorAll('.dropdown-item');

            if (dropdownButton) {
                dropdownButton.textContent = getDefaultTextForDropdown(id);
                dropdownButton.classList.remove('active');
            }
            dropdownItems.forEach(item => {
                item.classList.remove('active');
            });
        });
        console.log("Executed");
        currentPage = 1;
        list.filter();

        const url = new URL(window.location.href);
        const newUrl = `${url.pathname}${url.hash}`;
        window.history.pushState({}, '', newUrl);

        updatePaginationInfo();
        updatePaginationButtons();
        updateRowNumbers();
    }
}