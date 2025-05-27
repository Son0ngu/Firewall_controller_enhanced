/**
 * Firewall Controller - Main Application JavaScript
 * 
 * This file contains shared functionality used across the web interface:
 * - WebSocket/Socket.IO connectivity for real-time updates
 * - AJAX helpers for interacting with the REST API
 * - UI utilities and event handlers
 * - Form processing and validation
 */

// Store application state
const App = {
    socket: null,
    realTimeEnabled: true,
    notificationsEnabled: true,
    settings: {
        animationsEnabled: true,
        soundEnabled: true
    },
    currentUser: null
};

/**
 * Initialize the application when the DOM is fully loaded
 */
document.addEventListener('DOMContentLoaded', function() {
    // Connect to WebSocket server
    initializeSocketIO();
    
    // Initialize UI components
    initializeUIComponents();
    
    // Setup event listeners
    setupEventListeners();
    
    // Setup notification sound
    setupNotificationSound();
    
    // Get user info if logged in
    fetchCurrentUser();
});

/**
 * Initialize Socket.IO connection for real-time updates
 */
function initializeSocketIO() {
    // Check if Socket.IO is loaded
    if (typeof io === 'undefined') {
        console.warn('Socket.IO not loaded. Real-time updates will not be available.');
        updateConnectionStatus(false, 'Socket.IO not loaded');
        return;
    }
    
    try {
        // Connect to the Socket.IO server
        App.socket = io();
        
        // Connection event handlers
        App.socket.on('connect', function() {
            console.log('Connected to WebSocket server');
            updateConnectionStatus(true);
            
            // Request initial data
            if (document.getElementById('logsTableBody')) {
                // Only on pages with logs table
                App.socket.emit('subscribe_logs');
            }
        });
        
        App.socket.on('disconnect', function() {
            console.log('Disconnected from WebSocket server');
            updateConnectionStatus(false, 'Disconnected');
        });
        
        App.socket.on('connect_error', function(error) {
            console.error('WebSocket connection error:', error);
            updateConnectionStatus(false, 'Connection error');
        });
        
        // Log related events
        App.socket.on('new_log', function(data) {
            if (!App.realTimeEnabled) return;
            
            console.log('New log received:', data);
            
            // Update dashboard counters if they exist
            updateDashboardCounters(data);
            
            // Add log to table if on dashboard or logs page
            const logsTable = document.getElementById('logsTableBody');
            if (logsTable) {
                addLogToTable(logsTable, data);
            }
            
            // Show notification for blocked domains
            if (data.action === 'block' && App.notificationsEnabled) {
                showBlockNotification(data);
            }
        });
        
        // Whitelist related events
        App.socket.on('whitelist_updated', function(data) {
            console.log('Whitelist updated:', data);
            
            // Show notification
            showNotification('success', `Domain "${data.domain}" ${data.action === 'add' ? 'added to' : data.action === 'update' ? 'updated in' : 'removed from'} whitelist`);
            
            // Update whitelist table if on admin page
            if (window.location.pathname.includes('/admin') && typeof refreshWhitelistTable === 'function') {
                refreshWhitelistTable();
            }
        });
        
        App.socket.on('whitelist_bulk_updated', function(data) {
            console.log('Bulk whitelist update:', data);
            
            // Show notification
            showNotification('info', `${data.count} domains ${data.action === 'bulk_add' ? 'added to' : 'removed from'} whitelist`);
            
            // Update whitelist table if on admin page
            if (window.location.pathname.includes('/admin') && typeof refreshWhitelistTable === 'function') {
                refreshWhitelistTable();
            }
        });
        
        // Agent related events
        App.socket.on('agent_status_change', function(data) {
            console.log('Agent status changed:', data);
            
            // Show notification
            showNotification(data.status === 'online' ? 'success' : 'warning', 
                            `Agent "${data.hostname || data.agent_id}" is now ${data.status}`);
            
            // Update agents table if on agents page
            if (window.location.pathname.includes('/agents') && typeof refreshAgentsTable === 'function') {
                refreshAgentsTable();
            }
        });
        
        // User related events
        App.socket.on('user_updated', function(data) {
            console.log('User updated:', data);
            
            // Only show notification for admin users
            if (App.currentUser && App.currentUser.role === 'admin') {
                showNotification('info', `User "${data.username}" was ${data.action}`);
                
                // Update users table if on admin page
                if (window.location.pathname.includes('/admin') && document.getElementById('users-tab') && typeof refreshUserTable === 'function') {
                    refreshUserTable();
                }
            }
        });
        
        // Alert events (high priority notifications)
        App.socket.on('alert', function(data) {
            console.log('Alert received:', data);
            
            // Always show alerts regardless of notification settings
            showAlert('danger', data.message, data.title || 'Alert');
            
            // Play alert sound
            playNotificationSound('alert');
        });
    } catch (error) {
        console.error('Error initializing Socket.IO:', error);
        updateConnectionStatus(false, 'Initialization error');
    }
}

/**
 * Update the connection status indicator if present on the page
 */
function updateConnectionStatus(connected, message = null) {
    const statusElement = document.getElementById('connectionStatus');
    if (!statusElement) return;
    
    if (connected) {
        statusElement.innerHTML = '<i class="fas fa-check-circle me-1"></i>Connected';
        statusElement.className = 'badge bg-success me-2';
    } else {
        statusElement.innerHTML = `<i class="fas fa-times-circle me-1"></i>${message || 'Disconnected'}`;
        statusElement.className = 'badge bg-danger me-2';
    }
}

/**
 * Initialize various UI components
 */
function initializeUIComponents() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach(function(tooltipTriggerEl) {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.forEach(function(popoverTriggerEl) {
        new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Setup theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleDarkMode);
        
        // Set initial state based on localStorage or user preference
        if (localStorage.getItem('darkMode') === 'enabled' || 
            (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches && 
             localStorage.getItem('darkMode') !== 'disabled')) {
            document.body.classList.add('dark-mode');
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        }
    }
}

/**
 * Set up global event listeners
 */
function setupEventListeners() {
    // Toggle real-time updates
    const realTimeToggle = document.getElementById('realTimeUpdates');
    if (realTimeToggle) {
        realTimeToggle.addEventListener('change', function() {
            App.realTimeEnabled = this.checked;
            localStorage.setItem('realTimeEnabled', App.realTimeEnabled.toString());
        });
        
        // Set initial state from localStorage
        const storedPreference = localStorage.getItem('realTimeEnabled');
        if (storedPreference !== null) {
            App.realTimeEnabled = storedPreference === 'true';
            realTimeToggle.checked = App.realTimeEnabled;
        }
    }
    
    // Whitelist form handling
    setupWhitelistFormHandlers();
    
    // Domain search functionality
    setupDomainSearch();
    
    // Log filtering functionality
    setupLogFilters();
}

/**
 * Set up notification sound
 */
function setupNotificationSound() {
    // Create audio elements if they don't exist
    if (!document.getElementById('notificationSound')) {
        const notificationSound = document.createElement('audio');
        notificationSound.id = 'notificationSound';
        notificationSound.src = '/static/sounds/notification.mp3';
        notificationSound.preload = 'auto';
        document.body.appendChild(notificationSound);
    }
    
    if (!document.getElementById('alertSound')) {
        const alertSound = document.createElement('audio');
        alertSound.id = 'alertSound';
        alertSound.src = '/static/sounds/alert.mp3';
        alertSound.preload = 'auto';
        document.body.appendChild(alertSound);
    }
}

/**
 * Play notification sound
 * @param {string} type - 'notification' or 'alert'
 */
function playNotificationSound(type = 'notification') {
    if (!App.settings.soundEnabled) return;
    
    const soundId = type === 'alert' ? 'alertSound' : 'notificationSound';
    const sound = document.getElementById(soundId);
    
    if (sound) {
        sound.currentTime = 0;
        sound.play().catch(err => console.warn('Could not play notification sound:', err));
    }
}

/**
 * Toggle dark/light mode
 */
function toggleDarkMode() {
    const body = document.body;
    body.classList.toggle('dark-mode');
    
    const themeToggle = document.getElementById('themeToggle');
    
    if (body.classList.contains('dark-mode')) {
        localStorage.setItem('darkMode', 'enabled');
        if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    } else {
        localStorage.setItem('darkMode', 'disabled');
        if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
    }
}

/**
 * Set up whitelist form handlers (add, edit, delete, bulk import)
 */
function setupWhitelistFormHandlers() {
    // Add domain form
    const addDomainBtn = document.getElementById('saveDomainBtn');
    if (addDomainBtn) {
        addDomainBtn.addEventListener('click', function() {
            const domain = document.getElementById('domainName').value.trim();
            const notes = document.getElementById('domainNotes').value.trim();
            
            if (!domain) {
                showNotification('danger', 'Please enter a domain name');
                return;
            }
            
            // Call API to add domain
            addDomainToWhitelist(domain, notes);
        });
    }
    
    // Update domain form
    const updateDomainBtn = document.getElementById('updateDomainBtn');
    if (updateDomainBtn) {
        updateDomainBtn.addEventListener('click', function() {
            const domainId = document.getElementById('editDomainId').value;
            const domain = document.getElementById('editDomainName').value.trim();
            const notes = document.getElementById('editDomainNotes').value.trim();
            
            if (!domain) {
                showNotification('danger', 'Please enter a domain name');
                return;
            }
            
            // Call API to update domain
            updateWhitelistedDomain(domainId, domain, notes);
        });
    }
    
    // Bulk import handler
    const importDomainsBtn = document.getElementById('importDomainsBtn');
    if (importDomainsBtn) {
        importDomainsBtn.addEventListener('click', function() {
            const importType = document.getElementById('importType').value;
            const notes = document.getElementById('importNotes').value.trim();
            
            if (importType === 'text') {
                // Get domains from textarea
                const bulkDomains = document.getElementById('bulkDomains').value;
                const domains = bulkDomains.split('\n')
                    .map(line => line.trim())
                    .filter(line => line.length > 0);
                
                if (domains.length === 0) {
                    showNotification('danger', 'No domains to import');
                    return;
                }
                
                // Call API to bulk import domains
                bulkImportDomains(domains, notes);
            } else {
                // Process file upload
                processFileImport(notes);
            }
        });
    }
    
    // Import type toggle
    const importTypeSelect = document.getElementById('importType');
    if (importTypeSelect) {
        importTypeSelect.addEventListener('change', function() {
            const importType = this.value;
            
            document.getElementById('textImportSection').style.display = 
                importType === 'text' ? 'block' : 'none';
            document.getElementById('fileImportSection').style.display = 
                importType === 'file' ? 'block' : 'none';
        });
    }
    
    // Setup delete domain handlers
    setupDeleteDomainHandlers();
}

/**
 * Set up handlers for delete domain buttons
 * This needs to be called after table refresh as well
 */
function setupDeleteDomainHandlers() {
    document.querySelectorAll('.delete-domain-btn').forEach(button => {
        button.addEventListener('click', function() {
            const domainId = this.getAttribute('data-domain-id');
            const domain = this.getAttribute('data-domain');
            
            if (confirm(`Are you sure you want to remove "${domain}" from the whitelist?`)) {
                // Call API to delete domain
                deleteDomainFromWhitelist(domainId, domain);
            }
        });
    });
}

/**
 * Set up domain search functionality
 */
function setupDomainSearch() {
    const searchBtn = document.getElementById('searchDomainsBtn');
    const searchInput = document.getElementById('domainSearch');
    
    if (searchBtn && searchInput) {
        // Search when button is clicked
        searchBtn.addEventListener('click', performDomainSearch);
        
        // Search when Enter key is pressed
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performDomainSearch();
            }
        });
    }
}

/**
 * Perform domain search in whitelist table
 */
function performDomainSearch() {
    const searchTerm = document.getElementById('domainSearch').value.trim().toLowerCase();
    const typeFilter = document.getElementById('domainTypeFilter')?.value || '';
    
    const rows = document.querySelectorAll('#whitelistTable tbody tr');
    let visibleCount = 0;
    
    rows.forEach(row => {
        const domainCell = row.querySelector('td:first-child');
        const domain = domainCell.textContent.trim().toLowerCase();
        const isWildcard = domain.startsWith('*.');
        
        let visible = domain.includes(searchTerm);
        
        if (typeFilter === 'wildcard' && !isWildcard) {
            visible = false;
        } else if (typeFilter === 'exact' && isWildcard) {
            visible = false;
        }
        
        row.style.display = visible ? '' : 'none';
        if (visible) visibleCount++;
    });
    
    // Update result count if element exists
    const countElement = document.getElementById('visibleDomainCount');
    if (countElement) {
        countElement.textContent = visibleCount;
    }
}

/**
 * Set up log filtering functionality
 */
function setupLogFilters() {
    const applyFilterBtn = document.getElementById('applyFilterBtn');
    if (applyFilterBtn) {
        applyFilterBtn.addEventListener('click', function() {
            const agent = document.getElementById('agentFilter').value;
            const action = document.getElementById('actionFilter').value;
            const domain = document.getElementById('domainFilter').value;
            const timeRange = document.getElementById('timeRangeFilter').value;
            
            // Build query string
            let queryParams = [];
            if (agent) queryParams.push(`agent_id=${encodeURIComponent(agent)}`);
            if (action) queryParams.push(`action=${encodeURIComponent(action)}`);
            if (domain) queryParams.push(`domain=${encodeURIComponent(domain)}`);
            if (timeRange) queryParams.push(`time_range=${encodeURIComponent(timeRange)}`);
            
            // Redirect to filtered view
            window.location.href = `${window.location.pathname}?${queryParams.join('&')}`;
        });
    }
}

/**
 * Process file import for bulk domain whitelist
 */
function processFileImport(notes) {
    const fileInput = document.getElementById('domainFile');
    if (!fileInput.files || fileInput.files.length === 0) {
        showNotification('danger', 'Please select a file to import');
        return;
    }
    
    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
        const contents = e.target.result;
        let domains = contents.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
        
        // If CSV, extract first column
        if (file.name.endsWith('.csv')) {
            domains = domains.map(line => {
                const parts = line.split(',');
                return parts[0].trim().replace(/"/g, '');
            });
        }
        
        if (domains.length === 0) {
            showNotification('danger', 'No domains found in the file');
            return;
        }
        
        // Call API to bulk import domains
        bulkImportDomains(domains, notes);
    };
    
    reader.onerror = function() {
        showNotification('danger', 'Error reading file');
    };
    
    reader.readAsText(file);
}

/**
 * Update dashboard counters with new log data
 */
function updateDashboardCounters(data) {
    const totalElement = document.getElementById('totalLogs');
    const allowedElement = document.getElementById('allowedLogs');
    const blockedElement = document.getElementById('blockedLogs');
    
    if (totalElement) {
        totalElement.textContent = (parseInt(totalElement.textContent) + 1).toString();
    }
    
    if (data.action === 'allow' && allowedElement) {
        allowedElement.textContent = (parseInt(allowedElement.textContent) + 1).toString();
    } else if (data.action === 'block' && blockedElement) {
        blockedElement.textContent = (parseInt(blockedElement.textContent) + 1).toString();
    }
}

/**
 * Add a new log entry to the table
 */
function addLogToTable(tableBody, data) {
    // Format date
    const date = new Date(data.timestamp || Date.now());
    const formattedDate = date.toLocaleString();
    
    // Create row
    const row = document.createElement('tr');
    row.id = `log-${data._id}`;
    row.className = 'highlight';
    
    // Status icon and class
    const statusIcon = data.action === 'allow' ? 
        '<span class="status-allow"><i class="fas fa-check-circle me-1"></i>Allowed</span>' : 
        '<span class="status-block"><i class="fas fa-ban me-1"></i>Blocked</span>';
    
    // Get agent name (hostname or ID)
    const agentName = data.agent_hostname || data.agent_id;
    
    // Create the actions column content based on user role
    let actionsHtml = '';
    if (App.currentUser) {
        actionsHtml = `
            <div class="btn-group btn-group-sm">
                <button type="button" class="btn btn-outline-secondary view-log-btn" 
                        data-log-id="${data._id}" data-bs-toggle="modal" data-bs-target="#logDetailModal">
                    <i class="fas fa-eye"></i>
                </button>`;
                
        // Add delete button for admins
        if (App.currentUser.role === 'admin') {
            actionsHtml += `
                <button type="button" class="btn btn-outline-danger delete-log-btn" data-log-id="${data._id}">
                    <i class="fas fa-trash"></i>
                </button>`;
        }
        
        actionsHtml += `</div>`;
    }
    
    // Set row content
    row.innerHTML = `
        <td>${formattedDate}</td>
        <td>${agentName}</td>
        <td>${data.domain}</td>
        <td>${data.dest_ip}</td>
        <td>${data.protocol || 'HTTPS'}</td>
        <td>${statusIcon}</td>
        <td>${actionsHtml}</td>
    `;
    
    // Insert at the beginning of the table
    if (tableBody.firstChild) {
        tableBody.insertBefore(row, tableBody.firstChild);
    } else {
        tableBody.appendChild(row);
    }
    
    // Hide "no logs" message if it exists
    const noLogsMessage = document.getElementById('noLogsMessage');
    if (noLogsMessage) {
        noLogsMessage.style.display = 'none';
    }
    
    // Add event listeners to the new buttons
    const viewBtn = row.querySelector('.view-log-btn');
    if (viewBtn) {
        viewBtn.addEventListener('click', function() {
            fetchLogDetails(data._id);
        });
    }
    
    const deleteBtn = row.querySelector('.delete-log-btn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete this log?')) {
                deleteLog(data._id);
            }
        });
    }
    
    // Remove oldest row if we have more than 50
    const rows = tableBody.querySelectorAll('tr');
    if (rows.length > 50) {
        tableBody.removeChild(rows[rows.length - 1]);
    }
    
    // Play notification sound for blocks
    if (data.action === 'block') {
        playNotificationSound('notification');
    }
}

/**
 * Show notification for blocked domains
 */
function showBlockNotification(data) {
    // Create alert element
    showAlert('danger', `Connection to <strong>${data.domain}</strong> was blocked.`, 'Access Blocked');
}

/**
 * Show a notification in the alert container
 */
function showNotification(type, message) {
    const alertContainer = document.getElementById('alertContainer') || document.getElementById('liveAlertContainer');
    if (!alertContainer) return;
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.appendChild(alertDiv);
    
    // Remove after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

/**
 * Show an alert with title
 */
function showAlert(type, message, title = null) {
    const alertContainer = document.getElementById('liveAlertContainer');
    if (!alertContainer) return;
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    
    let content = '';
    if (title) {
        content = `<strong>${title}!</strong> ${message}`;
    } else {
        content = message;
    }
    
    alertDiv.innerHTML = `
        ${content}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.appendChild(alertDiv);
    
    // Play sound for important alerts
    if (type === 'danger') {
        playNotificationSound('alert');
    }
    
    // Remove after 6 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 6000);
}

/**
 * Fetch the current user's information
 */
function fetchCurrentUser() {
    fetch('/api/user/current')
        .then(response => response.json())
        .then(data => {
            if (!data.error && data.user) {
                App.currentUser = data.user;
                console.log('Current user:', App.currentUser);
            }
        })
        .catch(error => {
            console.error('Error fetching current user:', error);
        });
}

/**
 * Fetch log details for the log detail modal
 */
function fetchLogDetails(logId) {
    const contentDiv = document.getElementById('logDetailContent');
    const whitelistBtn = document.getElementById('whitelistDomainBtn');
    
    if (!contentDiv) return;
    
    // Show loading spinner
    contentDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    // Fetch log details
    fetch(`/api/logs/${logId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                contentDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            // Format date
            const date = new Date(data.timestamp);
            const formattedDate = date.toLocaleString();
            
            // Set domain for whitelist button if it exists
            if (whitelistBtn) {
                whitelistBtn.setAttribute('data-domain', data.domain);
            }
            
            // Build details HTML
            let detailsHtml = `
                <div class="row">
                    <div class="col-md-6">
                        <h6>Basic Information</h6>
                        <dl class="row">
                            <dt class="col-sm-4">Time</dt>
                            <dd class="col-sm-8">${formattedDate}</dd>
                            
                            <dt class="col-sm-4">Domain</dt>
                            <dd class="col-sm-8">${data.domain}</dd>
                            
                            <dt class="col-sm-4">IP Address</dt>
                            <dd class="col-sm-8">${data.dest_ip}</dd>
                            
                            <dt class="col-sm-4">Protocol</dt>
                            <dd class="col-sm-8">${data.protocol || 'HTTPS'}</dd>
                            
                            <dt class="col-sm-4">Port</dt>
                            <dd class="col-sm-8">${data.dest_port || '443'}</dd>
                            
                            <dt class="col-sm-4">Action</dt>
                            <dd class="col-sm-8">
                                ${data.action === 'allow' ? 
                                '<span class="text-success">Allowed</span>' : 
                                '<span class="text-danger">Blocked</span>'}
                            </dd>
                        </dl>
                    </div>
                    <div class="col-md-6">
                        <h6>Agent Information</h6>
                        <dl class="row">
                            <dt class="col-sm-4">Agent ID</dt>
                            <dd class="col-sm-8">${data.agent_id}</dd>
                            
                            <dt class="col-sm-4">Hostname</dt>
                            <dd class="col-sm-8">${data.agent_hostname || 'N/A'}</dd>
                            
                            ${data.process_name ? `
                            <dt class="col-sm-4">Process</dt>
                            <dd class="col-sm-8">${data.process_name}</dd>
                            ` : ''}
                            
                            ${data.username ? `
                            <dt class="col-sm-4">User</dt>
                            <dd class="col-sm-8">${data.username}</dd>
                            ` : ''}
                        </dl>
                    </div>
                </div>
                
                <hr>
                
                <h6>Raw Data</h6>
                <pre class="bg-light p-3 rounded"><code>${JSON.stringify(data, null, 2)}</code></pre>
            `;
            
            contentDiv.innerHTML = detailsHtml;
        })
        .catch(error => {
            contentDiv.innerHTML = `<div class="alert alert-danger">Error loading log details: ${error.message}</div>`;
        });
}

/**
 * Delete a log entry
 */
function deleteLog(logId) {
    fetch(`/api/logs/${logId}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showNotification('danger', `Error: ${data.error}`);
            return;
        }
        
        // Remove row from table
        const row = document.getElementById(`log-${logId}`);
        if (row) {
            row.remove();
        }
        
        // Show success message
        showNotification('success', 'Log entry has been deleted');
    })
    .catch(error => {
        showNotification('danger', `Error deleting log: ${error.message}`);
    });
}

/**
 * Add a domain to the whitelist
 */
function addDomainToWhitelist(domain, notes = '') {
    fetch('/api/whitelist', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            domain: domain,
            notes: notes
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showNotification('danger', `Error: ${data.error}`);
            return;
        }
        
        // Clear form
        const domainNameInput = document.getElementById('domainName');
        const domainNotesInput = document.getElementById('domainNotes');
        if (domainNameInput) domainNameInput.value = '';
        if (domainNotesInput) domainNotesInput.value = '';
        
        // Close modal if it exists
        const modal = document.getElementById('addDomainModal');
        if (modal) {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) bsModal.hide();
        }
        
        // Show success notification
        showNotification('success', `Domain "${domain}" added to whitelist`);
        
        // If on admin page, refresh the whitelist table
        if (window.location.pathname.includes('/admin') && typeof refreshWhitelistTable === 'function') {
            refreshWhitelistTable();
        }
    })
    .catch(error => {
        showNotification('danger', `Error adding domain: ${error.message}`);
    });
}

/**
 * Update a whitelisted domain
 */
function updateWhitelistedDomain(domainId, domain, notes = '') {
    fetch(`/api/whitelist/${domainId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            domain: domain,
            notes: notes
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showNotification('danger', `Error: ${data.error}`);
            return;
        }
        
        // Close modal if it exists
        const modal = document.getElementById('editDomainModal');
        if (modal) {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) bsModal.hide();
        }
        
        // Show success notification
        showNotification('success', `Domain "${domain}" updated`);
        
        // If on admin page, refresh the whitelist table
        if (window.location.pathname.includes('/admin') && typeof refreshWhitelistTable === 'function') {
            refreshWhitelistTable();
        }
    })
    .catch(error => {
        showNotification('danger', `Error updating domain: ${error.message}`);
    });
}

/**
 * Delete a domain from the whitelist
 */
function deleteDomainFromWhitelist(domainId, domain) {
    fetch(`/api/whitelist/${domainId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showNotification('danger', `Error: ${data.error}`);
            return;
        }
        
        // Show success notification
        showNotification('success', `Domain "${domain}" removed from whitelist`);
        
        // If on admin page, refresh the whitelist table
        if (window.location.pathname.includes('/admin') && typeof refreshWhitelistTable === 'function') {
            refreshWhitelistTable();
        }
    })
    .catch(error => {
        showNotification('danger', `Error deleting domain: ${error.message}`);
    });
}

/**
 * Bulk import domains to the whitelist
 */
function bulkImportDomains(domains, notes = '') {
    fetch('/api/whitelist/bulk', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            domains: domains,
            notes: notes
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showNotification('danger', `Error: ${data.error}`);
            return;
        }
        
        // Clear form
        const bulkDomainsTextarea = document.getElementById('bulkDomains');
        const domainFileInput = document.getElementById('domainFile');
        const importNotesInput = document.getElementById('importNotes');
        
        if (bulkDomainsTextarea) bulkDomainsTextarea.value = '';
        if (domainFileInput) domainFileInput.value = '';
        if (importNotesInput) importNotesInput.value = '';
        
        // Close modal if it exists
        const modal = document.getElementById('bulkImportModal');
        if (modal) {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) bsModal.hide();
        }
        
        // Show success notification
        showNotification('success', `${data.added} domains imported successfully. ${data.skipped} skipped (already exist or invalid).`);
        
        // If on admin page, refresh the whitelist table
        if (window.location.pathname.includes('/admin') && typeof refreshWhitelistTable === 'function') {
            refreshWhitelistTable();
        }
    })
    .catch(error => {
        showNotification('danger', `Error importing domains: ${error.message}`);
    });
}

// Add a domain to whitelist from the log detail modal
document.addEventListener('click', function(e) {
    if (e.target && e.target.id === 'whitelistDomainBtn') {
        const domain = e.target.getAttribute('data-domain');
        if (domain) {
            addDomainToWhitelist(domain, 'Added from log details');
            
            // Close the modal
            const modal = document.getElementById('logDetailModal');
            if (modal) {
                const bsModal = bootstrap.Modal.getInstance(modal);
                if (bsModal) bsModal.hide();
            }
        }
    }
});