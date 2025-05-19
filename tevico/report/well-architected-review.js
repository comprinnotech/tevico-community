document.addEventListener('DOMContentLoaded', function () {
    renderDOM({ warDetails: war_report, reportsData: check_reports })
    setActiveNavLink();
    if (window.updateNavbarAccountInfo) {
        window.updateNavbarAccountInfo(account_id, account_name);
    }
});

const renderDOM = ({ warDetails, reportsData }) => {
    const pillarTabs = document.getElementById('pillar_tabs');
    const tabsContent = document.getElementById('tabs_content');
    const tableTemplate = document.getElementById('section-table-template');
    const sectionTemplate = document.getElementById('section-content-template');

    const createTabId = (name) => name.split(' ').join('-').toLowerCase();

    const createNavTab = (section) => {
        const tab = document.createElement('li');
        tab.className = 'nav-item';

        const tabLink = document.createElement('a');
        tabLink.className = 'nav-link';
        const id = createTabId(section.name);
        tabLink.href = `#${id}`;
        tabLink.textContent = section.name;
        tabLink.setAttribute('data-bs-toggle', 'tab');

        tab.appendChild(tabLink);
        return tab;
    };

    const createTableRow = (checkData, index) => {
        const row = document.createElement('tr');
        let statusHtml = '';
        switch (checkData.status) {
            case 'passed':
                statusHtml = `<span class="badge bg-softer-success">Passed</span>`;
                break;
            case 'failed':
                statusHtml = `<span class="badge bg-softer-danger">Failed</span>`;
                break;
            case 'skipped':
                statusHtml = `<span class="badge bg-soft-info">Skipped</span>`;
                break;
            case 'not_applicable':
                statusHtml = `<span class="badge bg-softer-info">Not Applicable</span>`;
                break;
            case 'unknown':
                statusHtml = `<span class="badge bg-softer-warning">Unknown</span>`;
                break;
            case 'errored':
                statusHtml = `<span class="badge bg-soft-danger">Errored</span>`;
                break;
            default:
                statusHtml = '-';
        }
        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${checkData.check_metadata.check_title}</td>
            <td class="text-capitalize">${checkData.check_metadata.severity}</td>
            <td>${checkData.check_metadata.service_name}</td>
            <td>${checkData.section}</td>
            <td>
                ${statusHtml}
            </td>
            <td><a href="check-details.html?id=${checkData.name}&from=war" class="btn btn-primary btn-sm">View Details</a></td>
        `;
        return row;
    };

    const createSectionContent = (section) => {
        const content = sectionTemplate.content.cloneNode(true);
        const container = content.querySelector('.card');
        const title = content.querySelector('h3');
        const description = content.querySelector('p');

        title.textContent = section.name;
        description.textContent = section.description;

        const tableContent = tableTemplate.content.cloneNode(true);
        const tbody = tableContent.querySelector('.table-tbody');

        let index = 0;
        section.checks.forEach((check) => {
            const checkData = reportsData.find(report =>
                report.check_metadata.check_id === check
            );
            if (checkData) {
                tbody.appendChild(createTableRow(checkData, index));
                index += 1;
            }
        });

        container.querySelector('.card-body').appendChild(tableContent);
        return container;
    };

    warDetails.sections.forEach(section => {
        pillarTabs.appendChild(createNavTab(section));

        const tabContent = document.createElement('div');
        tabContent.className = 'tab-pane';
        const id = createTabId(section.name);
        tabContent.id = id;
        tabContent.setAttribute('role', 'tabpanel');
        tabContent.setAttribute('aria-labelledby', `${section.name}-tab`);
        tabContent.setAttribute('tabindex', '0');

        tabContent.innerHTML = `<p>${section.description}</p>`;

        if (section.sections) {
            section.sections.forEach((subSection, index) => {
                const sectionContent = createSectionContent(subSection);
                if (index + 1 < section.sections.length) {
                    sectionContent.classList.add('mb-3');
                }
                tabContent.appendChild(sectionContent);
            });
        }

        tabsContent.appendChild(tabContent);
    });
    pillarTabs.firstElementChild.querySelector('a').classList.add('active');
    tabsContent.firstElementChild.classList.add('active', 'show');
};