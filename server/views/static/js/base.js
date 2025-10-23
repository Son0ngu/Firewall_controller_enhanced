/* Base UI helpers extracted from base.html */
(function () {
    // Enhanced notification system using Bootstrap toasts
    window.showNotification = function (type, message, duration = 5000) {
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer || typeof bootstrap === 'undefined') {
            console.warn('Toast container or Bootstrap not available');
            return;
        }

        const toastId = 'toast-' + Date.now();
        const icons = {
            success: 'fas fa-check-circle',
            danger: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle',
            primary: 'fas fa-bell'
        };

        const toastHtml = `
            <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="${icons[type] || icons.info} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;

        toastContainer.insertAdjacentHTML('beforeend', toastHtml);

        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement, { delay: duration });
        toast.show();

        toastElement.addEventListener('hidden.bs.toast', function () {
            toastElement.remove();
        });
    };

    window.showLoading = function (element) {
        if (element) {
            element.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Loading...';
            element.disabled = true;
        }
    };

    window.hideLoading = function (element, originalText) {
        if (element) {
            element.innerHTML = originalText;
            element.disabled = false;
        }
    };

    window.addEventListener('error', function (e) {
        console.error('Global error:', e.error || e.message);
        showNotification('danger', 'An unexpected error occurred. Please refresh the page.');
    });

    document.addEventListener('DOMContentLoaded', function () {
        document.body.style.opacity = '0';
        document.body.style.transition = 'opacity 0.3s ease';

        setTimeout(() => {
            document.body.style.opacity = '1';
        }, 100);
    });
})();