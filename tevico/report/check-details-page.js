document.addEventListener('DOMContentLoaded', function () {
    const id = getQueryParam('id');
    if (id) {
        const report = check_reports.find(item => item.name === id);
        if (report) {
            displayCheckDetails(report);
        } else {
            console.error('Report not found for ID:', id);
        }
        // fetch('./data/check_reports.json')
        //     .then(response => {
        //         if (!response.ok) {
        //             throw new Error('Network response was not ok');
        //         }
        //         return response.json();
        //     })
        //     .then(data => {
        //         const report = data.find(item => item.name === id);
        //         if (report) {
        //             displayCheckDetails(report);
        //         } else {
        //             console.error('Report not found for ID:', id);
        //         }
        //     })
        //     .catch(error => {
        //         console.error('Error loading check details:', error);
        //     });
    } else {
        console.error('No ID parameter provided in URL');
        window.location.href = 'index.html';
    }
});

function getQueryParam(paramName) {
    try {
        const param = new URLSearchParams(window.location.search).get(paramName);
        if (param === null) {
            throw new Error(`Query parameter '${paramName}' not found`);
        }
        return param;
    } catch (error) {
        console.error('Error getting query parameter:', error.message);
        return null;
    }
}

function displayCheckDetails(report) {
    const pageTitle = document.getElementById('page_title');
    pageTitle.textContent = report.check_metadata?.check_id;
    const framework = document.getElementById('framework_text');
    framework.textContent = report.framework;
    const checkTitle = document.getElementById('check_title_text');
    checkTitle.textContent = report.check_metadata?.check_title;
    const checkIdTitle = document.getElementById('check_id_text');
    checkIdTitle.textContent = report.check_metadata?.check_id;
    const descriptionText = document.getElementById('description_text');
    descriptionText.textContent = report.check_metadata?.description;
    const resourceIdTemplateText = document.getElementById('resource_id_template_text');
    resourceIdTemplateText.textContent = report.check_metadata?.resource_id_template;
    const resourceTypeText = document.getElementById('resource_type_text');
    resourceTypeText.textContent = report.check_metadata?.resource_type;
    const riskText = document.getElementById('risk_text');
    riskText.textContent = report.check_metadata?.risk;
    const serviceNameText = document.getElementById('service_name_text');
    serviceNameText.textContent = report.check_metadata?.service_name;
    const severity = document.getElementById('severity_text');
    severity.textContent = report.check_metadata?.severity;
}