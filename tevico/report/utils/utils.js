function setActiveNavLink() {
    const currentPath = window.location.pathname.split('/').pop() || './';
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');

    navLinks.forEach(link => {
        const href = link.getAttribute('href').split('/').pop();

        if (currentPath === 'check-details.html') {
            if (link.textContent.trim().toLowerCase() === 'browse') {
                link.classList.add('active');

                const parentLi = link.closest('.nav-item');
                if (parentLi) {
                    parentLi.classList.add('active');
                }
            }
        }
        else if (href === currentPath) {
            link.classList.add('active');

            const parentLi = link.closest('.nav-item');
            if (parentLi) {
                parentLi.classList.add('active');
            }
        }
    });
}

const getQueryParam = (paramName) => {
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