let currentPage = 1;
let list;

function updatePaginationInfo() {
    const totalItems = list.matchingItems.length;
    const pageSize = list.page;
    const startIndex = (currentPage - 1) * pageSize + 1;
    const endIndex = Math.min(startIndex + pageSize - 1, totalItems);

    const paginationInfo = document.querySelector('.pagination-info');
    if (paginationInfo) {
        paginationInfo.textContent = `${startIndex}-${endIndex} of ${totalItems}`;
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
        valueNames: ['sort-check_metadata.check_title', 'sort-check_metadata.severity', 'check_metadata.service_name', 'sort-section'],
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
    // fetch('./data/check_reports.json')
    //     .then(response => {
    //         if (!response.ok) {
    //             throw new Error('Network response was not ok');
    //         }
    //         return response.json();
    //     })
    //     .then(reportsData => {
    //         createDynamicTable({ reportsData });
    //         // initializeListJS();
    //     })
    //     .catch(error => {
    //         console.error('Error loading JSON:', error);
    //     });
});

function createDynamicTable({ reportsData }) {
    const headersArray = [{ label: 'check', key: 'check_metadata.check_title' }, { label: 'severity', key: 'check_metadata.severity' }, { label: 'service', key: 'check_metadata.service_name' }, { label: 'section', key: 'section' },]

    const table = document.createElement('table');
    table.className = 'table table-vcenter';

    const thead = document.createElement('thead');
    thead.className = 'sticky-top';
    const headerRow = document.createElement('tr');

    headersArray.forEach(header => {
        const th = document.createElement('th');
        const button = document.createElement('button');
        button.className = 'table-sort';
        button.setAttribute('data-sort', `sort-${header.key}`);
        button.textContent = header.label;
        th.appendChild(button);
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    tbody.className = 'table-tbody';
    reportsData.forEach(item => {
        const row = document.createElement('tr');
        headersArray.forEach(header => {
            const td = document.createElement('td');
            td.className = `sort-${header.key}`;
            td.textContent = header.key.split('.').reduce((obj, key) => obj && obj[key], item) || '';
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });
    table.appendChild(tbody);

    const container = document.getElementById("tableContainer");
    container.innerHTML = '';
    container.appendChild(table);
    initializeListJS();
}