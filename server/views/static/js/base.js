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

        const needsDarkText = (type === 'warning' || type === 'success');
        const textClass = needsDarkText ? 'text-dark' : 'text-white';
        const closeBtnClass = needsDarkText ? 'btn-close me-2 m-auto' : 'btn-close btn-close-white me-2 m-auto';

        const toastHtml = `
            <div id="${toastId}" class="toast align-items-center ${textClass} bg-${type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="${icons[type] || icons.info} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="${closeBtnClass}" data-bs-dismiss="toast"></button>
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

    // --- Custom Select Logic ---
    const customSelects = new Map();

    window.initCustomSelect = function(selectId) {
        const select = document.getElementById(selectId);
        if (!select) return;
        
        // Check if already initialized
        if (select.parentNode.classList.contains('custom-select-wrapper')) {
            window.updateCustomOptions(selectId); // Just update options if exists
            return; 
        }

        // Wrap select
        const wrapper = document.createElement('div');
        wrapper.className = 'custom-select-wrapper';
        select.parentNode.insertBefore(wrapper, select);
        wrapper.appendChild(select);

        // Create trigger
        const trigger = document.createElement('div');
        trigger.className = 'custom-select-trigger';
        trigger.tabIndex = 0; // Make focusable
        trigger.innerHTML = `<span class="selection">${select.options[select.selectedIndex]?.text || 'Select...'}</span>`;
        wrapper.appendChild(trigger);

        // Create options container
        const optionsDiv = document.createElement('div');
        optionsDiv.className = 'custom-options';
        wrapper.appendChild(optionsDiv);

        const positionOptions = () => {
            const modalBoundary = wrapper.closest('.modal-content');
            const boundaryRect = modalBoundary
                ? modalBoundary.getBoundingClientRect()
                : { top: 0, bottom: window.innerHeight };
            const triggerRect = trigger.getBoundingClientRect();
            const gap = 8;
            const menuHeight = optionsDiv.scrollHeight || 260;
            const availableBelow = boundaryRect.bottom - triggerRect.bottom - gap;
            const availableAbove = triggerRect.top - boundaryRect.top - gap;
            const openUp = availableBelow < menuHeight && availableAbove > availableBelow;
            const available = openUp ? availableAbove : availableBelow;

            optionsDiv.classList.toggle('drop-up', openUp);
            optionsDiv.style.maxHeight = `${Math.max(96, Math.min(menuHeight, available))}px`;
        };

        const closeOptions = () => {
            optionsDiv.classList.remove('open');
        };
        
        // Function to populate/update options
        const populateOptions = () => {
            optionsDiv.innerHTML = '';
            Array.from(select.options).forEach(option => {
                const div = document.createElement('div');
                div.className = `custom-option ${option.selected ? 'selected' : ''}`;
                div.dataset.value = option.value;
                div.textContent = option.text;
                
                div.addEventListener('click', (e) => {
                    e.stopPropagation();
                    select.value = option.value;
                    select.dispatchEvent(new Event('change')); // Trigger native change
                    
                    // Update UI
                    trigger.querySelector('.selection').textContent = option.text;
                    optionsDiv.querySelectorAll('.custom-option').forEach(el => el.classList.remove('selected'));
                    div.classList.add('selected');
                    closeOptions();
                });
                
                optionsDiv.appendChild(div);
            });
        };

        // Initial populate
        populateOptions();
        
        // Store update function for later use
        customSelects.set(selectId, populateOptions);

        // Toggle dropdown
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const shouldOpen = !optionsDiv.classList.contains('open');
            // Close others
            document.querySelectorAll('.custom-options').forEach(el => {
                if (el !== optionsDiv) el.classList.remove('open');
            });
            if (shouldOpen) {
                positionOptions();
                optionsDiv.classList.add('open');
            } else {
                closeOptions();
            }
        });

        trigger.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                trigger.click();
            } else if (e.key === 'Escape') {
                closeOptions();
            }
        });

        select.addEventListener('change', () => {
            const selectedOption = select.options[select.selectedIndex];
            if (selectedOption) {
                trigger.querySelector('.selection').textContent = selectedOption.text;
                optionsDiv.querySelectorAll('.custom-option').forEach(el => {
                    el.classList.toggle('selected', el.dataset.value === selectedOption.value);
                });
            }
        });

        if (select.form) {
            select.form.addEventListener('reset', () => {
                setTimeout(() => window.updateCustomOptions(selectId), 0);
            });
        }

        window.addEventListener('resize', () => {
            if (optionsDiv.classList.contains('open')) {
                positionOptions();
            }
        });
        
        // Handle click outside to close
        document.addEventListener('click', (e) => {
            if (!wrapper.contains(e.target)) {
                closeOptions();
            }
        });
    };

    window.updateCustomOptions = function(selectId) {
        if (customSelects.has(selectId)) {
            customSelects.get(selectId)();
            
            // Also update trigger text to match new selected value
            const select = document.getElementById(selectId);
            const trigger = select.nextElementSibling; // .custom-select-trigger
            if (trigger) {
                const selectedOption = select.options[select.selectedIndex];
                if (selectedOption) {
                    trigger.querySelector('.selection').textContent = selectedOption.text;
                }
            }
        }
    };
})();

// ========================================
// USER SESSION - fetch current user info & logout
// ========================================
(function() {
    // Fetch current user info for navbar
    SaintAPI.get('/api/admin/auth/me')
        .then(data => {
            if (data.success && data.user) {
                const u = data.user;
                const nameEl = document.getElementById('navUsername');
                const roleEl = document.getElementById('navUserRole');
                if (nameEl) nameEl.textContent = u.username || 'User';
                if (roleEl) roleEl.textContent = 'Role: ' + (u.role || 'unknown');
            }
        })
        .catch(() => {});

    // Logout function. SaintAPI.post automatically attaches the CSRF
    // token; we still redirect to /login on any failure so a stale
    // session doesn't trap the user on the current page.
    window.doLogout = function() {
        SaintAPI.post('/api/admin/auth/logout')
            .then(() => { window.location.href = '/login'; })
            .catch(() => { window.location.href = '/login'; });
    };
})();
