function loadNavbar() {
  const navbarHtml = `<header class="navbar navbar-expand-md navbar-light d-print-none sticky-top bg-white border-bottom shadow-sm">
    <div class="container-xl">
      <div class="navbar-brand">
        <div class="me-3">
          <span class="fs-5 fw-normal">Account ID:</span>
          <span id="accountId"></span>
        </div>
        <div>
            <span class="fs-5 fw-normal">Account Name:</span>
            <span id="accountName"></span>
        </div>
      </div>
    </div>
  </header>`;

  const pageWrapper = document.querySelector('.page-wrapper');
  if (pageWrapper) {
    pageWrapper.insertAdjacentHTML('afterbegin', navbarHtml);
    initNavbar();
    return Promise.resolve(navbarHtml);
  } else {
    const error = new Error('Page wrapper element not found');
    console.error('Error loading navbar:', error);
    return Promise.reject(error);
  }
}

function initNavbar() {
  const storedAccountId = localStorage.getItem('accountId');
  const storedAccountName = localStorage.getItem('accountName');

  if (storedAccountId && storedAccountName) {
    updateAccountInfo(storedAccountId, storedAccountName);
  }
}

function updateAccountInfo(accountId, accountName) {
  const accountIdElement = document.getElementById('accountId');
  const accountNameElement = document.getElementById('accountName');

  if (accountIdElement) {
    accountIdElement.textContent = accountId;
  }

  if (accountNameElement) {
    accountNameElement.textContent = accountName !== 'Unknown' ? accountName : '--';
  }

  localStorage.setItem('accountId', accountId);
  localStorage.setItem('accountName', accountName);
}

window.updateNavbarAccountInfo = updateAccountInfo;

document.addEventListener('DOMContentLoaded', loadNavbar);