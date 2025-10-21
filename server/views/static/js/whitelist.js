let itemsData = [];
let selectedItems = new Set();

// Type configurations
const typeConfigs = {
    domain: {
        title: 'Add Domain',
        label: 'Domain Name',
        placeholder: 'example.com',
        example: 'Examples: example.com, *.subdomain.com, *.example.*',
        icon: 'globe',
        help: 'Use wildcards (*) for subdomains and patterns'
    },
    ip: {
        title: 'Add IP Address',
        label: 'IP Address/Range',
        placeholder: '192.168.1.100',
        example: 'Examples: 192.168.1.100, 10.0.0.0/24, 172.16.0.1-172.16.0.254',
        icon: 'network-wired',
        help: 'Single IPs, CIDR notation, or IP ranges supported'
    },
    url: {
        title: 'Add URL Pattern',
        label: 'URL Pattern',
        placeholder: 'https://api.example.com/v1/*',
        example: 'Examples: https://api.com/v1/*, /webhooks/*, *.example.com/api/*',
        icon: 'link',
        help: 'Use wildcards (*) for URL patterns and paths'
    },
    port: {
        title: 'Add Port/Range',
        label: 'Port Number/Range',
        placeholder: '80',
        example: 'Examples: 80, 443, 8000-9000, 22,80,443',
        icon: 'door-open',
        help: 'Single ports, ranges (8000-9000), or comma-separated lists'
    },
    process: {
        title: 'Add Process',
        label: 'Process Name',
        placeholder: 'chrome.exe',
        example: 'Examples: chrome.exe, node.exe, python.exe, *.exe',
        icon: 'cogs',
        help: 'Executable names with optional wildcards'
    }
};

/**
 * Enhanced error handling for API responses
 */
function handleApiResponse(response) {
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return response.json().then(data => {
        //  FIX: Handle different response formats
        if (data.error) {
            throw new Error(data.error);
        }
        return data;
    });
}

/**
 * Notify function for displaying messages
 */
function notify(type, message) {
    if (typeof showNotification === 'function') {
        showNotification(type, message);
    } else if (type === 'danger') {
        console.error(message);
    } else if (type === 'warning') {
        console.warn(message);
    } else {
        console.log(message);
    }
}

/**
 * Toggle bulk actions panel visibility
 */
function toggleBulkActionsPanel() {
    if (selectedItems.size === 0) {
        notify('warning', 'Select at least one item to use bulk actions.');
        return;
    }
    const bulkActions = document.getElementById('bulkActions');
    if (bulkActions) {
        bulkActions.classList.toggle('show');
    }
}

/**
 * Refresh bulk actions UI elements
 */
function refreshBulkActionsUI() {
    const countEl = document.getElementById('selectedCount');
    if (countEl) {
        countEl.textContent = selectedItems.size;
    }

    const hasSelection = selectedItems.size > 0;
    const bulkActions = document.getElementById('bulkActions');
    if (!hasSelection && bulkActions) {
        bulkActions.classList.remove('show');
    }

    const deleteBtn = document.getElementById('bulkDeleteBtn');
    if (deleteBtn) {
        deleteBtn.disabled = !hasSelection;
    }
}

async function bulkDeleteItems() {
    if (selectedItems.size === 0) {
        notify('warning', 'Select items before deleting.');
        return;
    }

    if (!confirm(`Delete ${selectedItems.size} selected item(s)? This action cannot be undone.`)) {
        return;
    }

    const actionButtons = document.querySelectorAll('#bulkActions button');
    actionButtons.forEach(btn => btn.disabled = true);

    try {
        const response = await fetch('/api/whitelist/bulk-delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                item_ids: Array.from(selectedItems)
            })
        });

        const result = await handleApiResponse(response);
        const deleted = result.deleted_count ?? selectedItems.size;

        showSuccess(`${deleted} item(s) removed successfully.`);
        selectedItems.clear();
        await loadItems();
    } catch (error) {
        showError('Failed to delete items: ' + error.message);
    } finally {
        actionButtons.forEach(btn => btn.disabled = false);
        refreshBulkActionsUI();
    }
}

/**
 * Load items from API with better error handling
 */
async function loadItems() {
    try {
        console.log(' Loading whitelist items...');
        const response = await fetch('/api/whitelist').catch(err => ({ ok: false, statusText: err.message }));
        if (response.ok) {
            const data = await handleApiResponse(response);
            
            //  FIX: Handle different response formats
            if (data.domains && Array.isArray(data.domains)) {
                itemsData = data.domains;
            } else if (data.items && Array.isArray(data.items)) {
                itemsData = data.items;
            } else if (data.whitelist && Array.isArray(data.whitelist)) {
                itemsData = data.whitelist;
            } else if (Array.isArray(data)) {
                itemsData = data;
            } else {
                console.warn(' Unexpected data format:', data);
                itemsData = [];
            }
            
            console.log(' Loaded items:', itemsData.length);
            renderItems(itemsData);
            updateStatistics();
            selectedItems.clear();
            refreshBulkActionsUI();
        } else {
            console.error(' Failed to load items:', response.statusText);
            showError('Failed to load whitelist items');
            renderItems([]);
            updateStatistics();
            selectedItems.clear();
            refreshBulkActionsUI();
        }
        
    } catch (error) {
        console.error(' Error loading items:', error);
        showError('Error loading whitelist items: ' + error.message);
        renderItems([]);
        updateStatistics();
        selectedItems.clear();
        refreshBulkActionsUI();
    }
}

/**
 * Update statistics display
 */
function updateStatistics() {
    const total = itemsData.length;
    const active = itemsData.filter(item => item.active !== false).length;
    const domains = itemsData.filter(item => (item.type || 'domain') === 'domain').length;
    const ips = itemsData.filter(item => item.type === 'ip').length;
    
    document.getElementById('totalItemsCount').textContent = total;
    document.getElementById('activeItemsCount').textContent = active;
    document.getElementById('domainsCount').textContent = domains;
    document.getElementById('ipsCount').textContent = ips;
    document.getElementById('itemCount').textContent = total;
}

/**
 * Render items list
 */
function renderItems(items) {
    const container = document.getElementById('itemsContainer');

    if (items.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-list"></i>
                <h5 class="fw-bold">No Items in Whitelist</h5>
                <p>Start by adding trusted domains, IPs, URLs, or other resources.</p>
                <div class="d-flex justify-content-center gap-2 flex-wrap">
                    <button class="btn btn-success btn-sm" data-type="domain">
                        <i class="fas fa-globe me-1"></i>Add Domain
                    </button>
                    <button class="btn btn-info btn-sm" data-type="ip">
                        <i class="fas fa-network-wired me-1"></i>Add IP
                    </button>
                    <button class="btn btn-warning btn-sm" data-type="url">
                        <i class="fas fa-link me-1"></i>Add URL
                    </button>
                </div>
            </div>
        `;

        // Add event listeners for empty state buttons
        container.querySelectorAll('[data-type]').forEach(btn => {
            btn.addEventListener('click', () => showAddItemModal(btn.dataset.type));
        });
        return;
    }

    container.innerHTML = '';

    items.forEach((item, index) => {
        const isActive = item.active !== false;
        const itemType = item.type || 'domain';
        const value = item.value || item.domain || item.ip || item.url || item.port || item.process;
        const itemId = item.id || item._id || value;
        const statusInfo = isActive ?
            { class: 'active', text: 'Active', icon: 'check-circle' } :
            { class: 'inactive', text: 'Inactive', icon: 'times-circle' };
        const typeConfig = typeConfigs[itemType] || typeConfigs.domain;
        const created = item.added_date ? new Date(item.added_date).toLocaleDateString() : 'Unknown';

        const itemElement = document.createElement('div');
        itemElement.className = 'p-4 border-bottom item-row';
        itemElement.dataset.value = (value || '').toLowerCase();
        itemElement.dataset.status = isActive ? 'active' : 'inactive';
        itemElement.dataset.type = itemType;
        itemElement.dataset.scope = (item.scope || 'global').toLowerCase();

        itemElement.innerHTML = `
            <div class="row align-items-center">
                <div class="col-md-1">
                    <div class="form-check">
                        <input class="form-check-input item-checkbox" type="checkbox" 
                               value="${itemId}">
                    </div>
                </div>
                <div class="col-md-7">
                    <div class="d-flex align-items-center">
                        <div class="me-3">
                            <i class="fas fa-${typeConfig.icon} fa-2x text-success"></i>
                        </div>
                        <div>
                            <h6 class="mb-2 fw-bold">
                                <i class="fas fa-shield-alt me-2"></i>
                                ${value}
                            </h6>
                            <div class="d-flex align-items-center mb-2">
                                <span class="domain-status ${statusInfo.class}">
                                    <span class="pulse-indicator ${statusInfo.class}"></span>
                                    ${statusInfo.text}
                                </span>
                                <span class="type-badge ${itemType} ms-2">
                                    ${itemType.toUpperCase()}
                                </span>
                                <span class="domain-type-badge ${item.scope || 'global'} ms-2">
                                    ${item.scope === 'agent' ? 'Agent Specific' : 'Global'}
                                </span>
                            </div>
                            <div class="row text-muted">
                                <div class="col-md-6">
                                    <small>
                                        <i class="fas fa-calendar me-1"></i>
                                        Added: ${created}
                                    </small>
                                </div>
                                ${item.agent_id ? `
                                    <div class="col-md-6">
                                        <small>
                                            <i class="fas fa-laptop-code me-1"></i>
                                            Agent: ${item.agent_id}
                                        </small>
                                    </div>
                                ` : ''}
                            </div>
                            ${item.notes ? `
                                <div class="mt-2">
                                    <small class="text-muted">
                                        <i class="fas fa-sticky-note me-1"></i>
                                        ${item.notes}
                                    </small>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                <div class="col-md-4 text-end">
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-danger btn-action"
                                data-action="remove"
                                data-item-id="${itemId}"
                                title="Remove this item">
                            <i class="fas fa-trash-alt me-1"></i>
                            <span>Remove</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        container.appendChild(itemElement);
    });
    
    // Add event listeners for action buttons
    container.querySelectorAll('[data-action]').forEach(btn => {
        btn.addEventListener('click', handleItemAction);
    });
    
    // Add event listeners for checkboxes
    container.querySelectorAll('.item-checkbox').forEach(cb => {
        cb.addEventListener('change', updateSelectedItems);
    });
}

/**
 * Show add item modal for specific type
 */
function showAddItemModal(type = 'domain') {
    const config = typeConfigs[type] || typeConfigs.domain;
    const modal = new bootstrap.Modal(document.getElementById('addItemModal'));
    
    // Update modal content based on type
    document.getElementById('modalTitle').innerHTML = `
        <i class="fas fa-${config.icon} me-2"></i>${config.title}
    `;
    document.getElementById('itemType').value = type;
    document.getElementById('valueLabel').textContent = config.label;
    document.getElementById('valueInput').placeholder = config.placeholder;
    document.getElementById('valueExample').textContent = config.help;
    document.getElementById('inputExample').textContent = config.example;
    
    // Load agents for agent-specific items
    loadAgentsForSelect();
    
    modal.show();
}

/**
 * Show bulk import modal
 */
function showBulkImportModal() {
    const modal = new bootstrap.Modal(document.getElementById('bulkImportModal'));
    modal.show();
}

/**
 * Handle item actions -  FIXED to call actual APIs
 */
async function handleItemAction(event) {
    const action = event.currentTarget.dataset.action;
    const itemId = event.currentTarget.dataset.itemId;
    console.log('🎯 Item action:', { action, itemId });

        if (action === 'remove') {
        await removeItem(itemId);
    }
}

/**
 * Remove item -  FIXED to call API
 */
async function removeItem(itemId) {
    if (!confirm('Are you sure you want to remove this item?')) return;
    
    try {
        console.log(' Removing item:', itemId);
        
        const response = await fetch(`/api/whitelist/${itemId}`, {
            method: 'DELETE'
        });
        
        const result = await handleApiResponse(response);
        console.log(' Remove result:', result);
        
        showSuccess(result.message || 'Item removed successfully');
        
        // Reload data from server
        await loadItems();
        
    } catch (error) {
        console.error(' Error removing item:', error);
        showError('Failed to remove item: ' + error.message);
    }
}

/**
 * Add new item -  FIXED to actually call API
 */
async function addItem() {
    const form = document.getElementById('addItemForm');
    const formData = new FormData(form);
    
    const button = document.getElementById('addItemSubmitBtn');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Adding...';
    button.disabled = true;
    
    try {
        const itemData = {
            type: formData.get('item_type'),
            value: formData.get('value'),
            scope: formData.get('scope') || 'global',
            description: formData.get('description'),
            notes: formData.get('notes') || '',
            active: formData.get('active') === 'on'
        };
        
        if (formData.get('scope') === 'agent') {
            itemData.agent_id = formData.get('agent_id');
        }
        
        console.log(' Sending item data:', itemData);
        
        //  FIX: Actually call the API instead of manipulating local array
        const response = await fetch('/api/whitelist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(itemData)
        });
        
        const result = await handleApiResponse(response);
        console.log(' API response:', result);
        
        showSuccess(result.message || `${itemData.type.toUpperCase()} ${itemData.value} added successfully!`);
        
        // Reset form and close modal
        form.reset();
        bootstrap.Modal.getInstance(document.getElementById('addItemModal')).hide();
        
        //  FIX: Reload data from server instead of manipulating local array
        await loadItems();
        
    } catch (error) {
        console.error(' Error adding item:', error);
        showError('Failed to add item: ' + error.message);
    } finally {
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

/**
 * Show error message
 */
function showError(message) {
    // Create error notification
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed';
    errorDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    errorDiv.innerHTML = `
        <i class="fas fa-exclamation-triangle me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(errorDiv);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (errorDiv.parentNode) {
            errorDiv.remove();
        }
    }, 5000);
}

/**
 * Show success message
 */
function showSuccess(message) {
    // Create success notification
    const successDiv = document.createElement('div');
    successDiv.className = 'alert alert-success alert-dismissible fade show position-fixed';
    successDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    successDiv.innerHTML = `
        <i class="fas fa-check-circle me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(successDiv);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        if (successDiv.parentNode) {
            successDiv.remove();
        }
    }, 3000);
}

/**
 * Other functions (simplified for demo)
 */
async function loadAgentsForSelect() {
    // Placeholder for loading agents
    console.log('Loading agents for selection...');
}

function refreshItems() {
    loadItems();
}

function showBulkActions() {
    const bulkActions = document.getElementById('bulkActions');
    bulkActions.classList.toggle('show');
}

function updateSelectedItems() {
    const checkboxes = document.querySelectorAll('.item-checkbox:checked');
    selectedItems.clear();

    checkboxes.forEach(cb => selectedItems.add(cb.value));
    refreshBulkActionsUI();
}

function filterItems() {
    const searchTerm = document.getElementById('item-search').value.toLowerCase();
    const typeFilter = document.getElementById('type-filter').value;
    const statusFilter = document.getElementById('status-filter').value;
    const scopeFilter = document.getElementById('scope-filter').value;
    const itemRows = document.querySelectorAll('.item-row');

    itemRows.forEach(row => {
        const value = row.dataset.value;
        const type = row.dataset.type;
        const status = row.dataset.status;
        const scope = row.dataset.scope || 'global';
        
        const matchesSearch = value.includes(searchTerm);
        const matchesType = !typeFilter || type === typeFilter;
        const matchesStatus = !statusFilter || status === statusFilter;
        const matchesScope = !scopeFilter || scope === scopeFilter;
        
        if (matchesSearch && matchesType && matchesStatus && matchesScope) {
            row.style.display = 'block';
        } else {
            row.style.display = 'none';
        }
    });
}

/**
 * Initialize page
 */
document.addEventListener('DOMContentLoaded', function() {
    // Add item type cards
    document.querySelectorAll('.add-item-card').forEach(card => {
        card.addEventListener('click', function() {
            const type = this.dataset.type;
            if (type === 'bulk') {
                showBulkImportModal();
            } else {
                showAddItemModal(type);
            }
        });
    });
    
    // Modal submit button
    document.getElementById('addItemSubmitBtn').addEventListener('click', addItem);
    
    // Filter and search
    document.getElementById('item-search').addEventListener('input', filterItems);
    document.getElementById('type-filter').addEventListener('change', filterItems);
    document.getElementById('status-filter').addEventListener('change', filterItems);
    document.getElementById('scope-filter').addEventListener('change', filterItems);
    
    // Control buttons
    document.getElementById('refreshBtn').addEventListener('click', refreshItems);
    document.getElementById('bulkActionsBtn').addEventListener('click', toggleBulkActionsPanel);
    document.getElementById('bulkDeleteBtn').addEventListener('click', bulkDeleteItems);
    
    // Scope selection handler
    document.getElementById('scopeSelect').addEventListener('change', function() {
        const agentGroup = document.getElementById('agentSelectGroup');
        if (this.value === 'agent') {
            agentGroup.style.display = 'block';
        } else {
            agentGroup.style.display = 'none';
        }
    });
    
    // Bulk import method toggle
    document.querySelectorAll('[name="importMethod"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const textSection = document.getElementById('textImportSection');
            const fileSection = document.getElementById('fileImportSection');
            
            if (this.value === 'text') {
                textSection.style.display = 'block';
                fileSection.style.display = 'none';
            } else {
                textSection.style.display = 'none';
                fileSection.style.display = 'block';
            }
        });
    });
    
    // Load initial data
    loadItems();
    
    // Auto-refresh every 60 seconds
    setInterval(loadItems, 60000);
    
    console.log(' Enhanced whitelist management initialized');
});