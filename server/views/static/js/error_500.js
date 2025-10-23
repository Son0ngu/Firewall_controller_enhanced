(function () {
    document.addEventListener('DOMContentLoaded', function () {
        const timestampEl = document.getElementById('error-timestamp');
        const sessionEl = document.getElementById('session-id');
        const userAgentEl = document.getElementById('user-agent');
        const refererEl = document.getElementById('referer');

        if (timestampEl) {
            timestampEl.textContent = new Date().toLocaleString();
        }
        if (sessionEl) {
            sessionEl.textContent = 'SES-' + Math.random().toString(36).substr(2, 9);
        }
        if (userAgentEl) {
            userAgentEl.textContent = navigator.userAgent.substring(0, 100) + '...';
        }
        if (refererEl) {
            refererEl.textContent = document.referrer || 'Direct access';
        }

        checkSystemHealth();
    });

    window.retryPage = function (evt) {
        const button = evt?.currentTarget || evt?.target;
        if (button) {
            const originalText = button.innerHTML;
            button.dataset.originalText = originalText;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Retrying...';
            button.disabled = true;

            setTimeout(() => {
                button.innerHTML = button.dataset.originalText || originalText;
                button.disabled = false;
                window.location.reload();
            }, 1000);
        } else {
            window.location.reload();
        }
    };

    window.reportIssue = function () {
        const errorInfo = {
            timestamp: new Date().toISOString(),
            url: window.location.href,
            userAgent: navigator.userAgent,
            referer: document.referrer || 'Direct access'
        };

        alert(`Issue Report Generated:\n\nTimestamp: ${errorInfo.timestamp}\nURL: ${errorInfo.url}\nBrowser: ${errorInfo.userAgent.substring(0, 50)}...\n\nPlease save this information and contact support if the issue persists.`);
        console.error('500 Error Report:', errorInfo);
    };

    async function checkSystemHealth() {
        await Promise.all([
            updateStatus('/api/health', 'server-status'),
            updateStatus('/api/database/status', 'db-status'),
            updateStatus('/api/socket/status', 'socket-status')
        ]);
    }

    async function updateStatus(endpoint, elementId) {
        const target = document.getElementById(elementId);
        if (!target) {
            return;
        }

        try {
            const response = await fetch(endpoint);
            const data = await response.json();

            if (response.ok) {
                target.innerHTML = '<small class="text-success"><i class="fas fa-check me-1"></i>Online</small>';
            } else {
                target.innerHTML = `<small class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>${data.message || 'Issue detected'}</small>`;
            }
        } catch (error) {
            target.innerHTML = '<small class="text-danger"><i class="fas fa-times me-1"></i>Unavailable</small>';
            console.error(`Health check failed for ${endpoint}:`, error);
        }
    }
})();