let groupAgents = [];
let allAgents = [];
let selectedAgents = new Set();
let agentPolicies = {};        // { agent_id: { override_mode, reason, ... } }
let customWlDomains = [];      // Temp state for custom whitelist modal
let ctxTargetAgentId = null;   // Agent currently targeted by context menu
let wlEntries = [];            // Inline whitelist editor state
let wlAllEntries = [];         // Unfiltered copy for search
let currentView = 'list';      // Map/list view state (must be before first usage)
const groupId = document.getElementById('groupId').value;

// Whitelist Profiles state
let wpProfiles = [];
// wpEditDomains removed - profile domains now edited on /whitelist page
let wpAssignedTeachers = [];   // Current assigned teacher ObjectIds

// ========================================
// INITIALIZATION
// ========================================

document.addEventListener('DOMContentLoaded', function() {
    SaintLog.debug('Group detail page initialized for:', groupId);
    
    loadGroupAgents();
    setupEventListeners();
    setupSocketIO();
    formatDates();
    wlLoadEntries();
    wpLoadProfiles();
    wpLoadTeachers();
    
    // Initialize custom select for status filter
    if (typeof initCustomSelect === 'function') {
        initCustomSelect('statusFilter');
    }
});

function setupEventListeners() {
    // Search and filter
    document.getElementById('agentSearch')?.addEventListener('input', filterGroupAgents);
    document.getElementById('statusFilter')?.addEventListener('change', filterGroupAgents);
    
    // Available agents search
    document.getElementById('availableAgentSearch')?.addEventListener('input', filterAvailableAgents);
    
    // Confirm add agents button
    document.getElementById('confirmAddAgents')?.addEventListener('click', addSelectedAgents);

    // Unassigned agents search in Assign Modal
    document.getElementById('unassignedAgentSearch')?.addEventListener('input', filterUnassignedAgentsList);
}

function setupSocketIO() {
    if (typeof io === 'undefined') {
        console.warn('Socket.IO not available');
        return;
    }
    
    const socket = io();
    
    socket.on('agent_heartbeat', (data) => {
        updateAgentStatus(data.agent_id, data.status, data);
    });
    
    socket.on('agent_group_updated', (data) => {
        if (data.group_id === groupId || groupAgents.some(a => a.agent_id === data.agent_id)) {
            loadGroupAgents();
        }
    });
    
    socket.on('agent_policy_changed', (data) => {
        if (groupAgents.some(a => a.agent_id === data.agent_id)) {
            // Update local policy cache + re-render
            agentPolicies[data.agent_id] = {
                override_mode: data.override_mode,
                reason: data.reason,
                applied_by_username: data.applied_by,
                expires_at: data.expires_at,
            };
            if (currentView === 'map') {
                renderGroupMap(groupAgents);
            } else {
                renderGroupAgents(groupAgents);
            }
        }
    });

    socket.on('connect', () => {
        SaintLog.debug('Socket.IO connected');
    });
}

function formatDates() {
    const createdEl = document.getElementById('groupCreated');
    const updatedEl = document.getElementById('groupUpdated');
    
    if (createdEl && createdEl.textContent) {
        createdEl.textContent = formatTimestamp(createdEl.textContent);
    }
    if (updatedEl && updatedEl.textContent) {
        updatedEl.textContent = formatTimestamp(updatedEl.textContent);
    }
}

// ========================================
// DATA LOADING
// ========================================

async function loadGroupAgents() {
    try {
        const data = await SaintAPI.get(`/api/agents?group_id=${groupId}`);
        groupAgents = data.agents || [];

        SaintLog.debug(`Loaded ${groupAgents.length} agents for group`);

        // Load policies for all agents in parallel
        await loadAgentPolicies(groupAgents.map(a => a.agent_id));

        if (currentView === 'map') {
            renderGroupMap(groupAgents);
        } else {
            renderGroupAgents(groupAgents);
        }
        updateStatistics();

    } catch (error) {
        console.error('Error loading group agents:', error);
        showError('Failed to load agents');
    }
}

async function loadAgentPolicies(agentIds) {
    // Load policy for each agent (batch would be better but individual is fine for now)
    const promises = agentIds.map(async (id) => {
        try {
            const result = await SaintAPI.get(`/api/agents/${id}/policy`);
            if (result.success && result.data) {
                agentPolicies[id] = result.data;
            }
        } catch (e) {
            // Policy not found = none, which is fine.
            // SaintAPI throws on non-2xx; swallow silently.
        }
    });
    await Promise.all(promises);
}

async function loadAllAgents() {
    try {
        // Ask server to exclude agents already in this group so the picker only shows available ones
        const data = await SaintAPI.get(`/api/agents?exclude_group_id=${groupId}`);
        allAgents = data.agents || [];

        return allAgents;
    } catch (error) {
        console.error('Error loading all agents:', error);
        return [];
    }
}

function refreshGroupAgents() {
    const btn = event?.target;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Refreshing...';
    }
    
    loadGroupAgents().finally(() => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt me-1"></i>Refresh';
        }
    });
}

// ========================================
// RENDERING
// ========================================

function renderGroupAgents(agents) {
    const container = document.getElementById('groupAgentsContainer');
    
    if (!agents || agents.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">
                    <i class="fas fa-users"></i>
                </div>
                <h5 class="fw-bold mt-3">No Agents in this Group</h5>
                <p class="text-muted mb-4">Add agents to this group to manage them together.</p>
                ${window.SAINT_AUTH && window.SAINT_AUTH.isAdmin ? `
                <button class="btn btn-primary" onclick="openAddAgentModal()">
                    <i class="fas fa-plus me-2"></i>Add Agent
                </button>` : ''}
            </div>
        `;
        return;
    }
    
    container.innerHTML = agents.map(agent => renderAgentItem(agent)).join('');
    
    // Update count
    document.getElementById('agentCount').textContent = agents.length;
}

function renderAgentItem(agent) {
    const statusInfo = getStatusInfo(agent.status);
    const displayName = agent.display_name || agent.hostname || agent.agent_id;
    const lastSeen = formatTimestamp(agent.last_heartbeat);

    // Policy badge for list view
    const policy = agentPolicies[agent.agent_id];
    const policyMode = policy?.override_mode || 'none';
    let policyBadgeHtml = '';
    if (policyMode === 'isolate') {
        policyBadgeHtml = '<span class="badge bg-danger ms-2" title="Network Isolated"><i class="fas fa-ban me-1"></i>Isolated</span>';
    } else if (policyMode === 'custom_whitelist') {
        policyBadgeHtml = '<span class="badge bg-warning text-dark ms-2" title="Custom Whitelist"><i class="fas fa-list-alt me-1"></i>Custom</span>';
    }

    return `
        <div class="group-agent-item" data-agent-id="${agent.agent_id}"
             data-name="${(displayName + ' ' + (agent.hostname || '')).toLowerCase()}"
             data-ip="${(agent.ip_address || '').toLowerCase()}"
             data-status="${agent.status || 'unknown'}"
             oncontextmenu="showAgentContextMenu(event, '${agent.agent_id}')">
            <div class="agent-info">
                <div class="agent-avatar">
                    <i class="fas fa-desktop"></i>
                </div>
                <div class="agent-details">
                    <h6>${escapeHtml(displayName)}${policyBadgeHtml}</h6>
                    <div class="agent-meta">
                        <small><i class="fas fa-network-wired me-1"></i>${agent.ip_address || 'Unknown IP'}</small>
                        <small><i class="fas fa-clock me-1"></i>${lastSeen}</small>
                    </div>
                </div>
            </div>
            <div class="d-flex align-items-center gap-2">
                <span class="status-badge ${statusInfo.class}">
                    <span class="status-dot ${statusInfo.class}"></span>
                    ${statusInfo.text}
                </span>
                <div class="agent-actions">
                    <button class="btn btn-sm btn-outline-primary" onclick="viewAgentLogs('${agent.agent_id}')" title="View Logs">
                        <i class="fas fa-file-alt"></i>
                    </button>
                    ${window.SAINT_AUTH && window.SAINT_AUTH.isAdmin ? `
                    <button class="btn btn-sm btn-outline-danger" onclick="removeAgentFromGroup('${agent.agent_id}')" title="Remove from Group">
                        <i class="fas fa-user-minus"></i>
                    </button>` : ''}
                </div>
            </div>
        </div>
    `;
}

function updateStatistics() {
    const total = groupAgents.length;
    const active = groupAgents.filter(a => a.status === 'active').length;
    const inactive = groupAgents.filter(a => a.status === 'inactive').length;
    const offline = groupAgents.filter(a => a.status === 'offline' || !a.status).length;
    
    document.getElementById('statTotal').textContent = total;
    document.getElementById('statActive').textContent = active;
    document.getElementById('statInactive').textContent = inactive;
    document.getElementById('statOffline').textContent = offline;
    document.getElementById('agentCount').textContent = total;
}

// ========================================
// ADD AGENT MODAL
// ========================================

async function openAddAgentModal() {
    if (!(window.SAINT_AUTH && window.SAINT_AUTH.isAdmin)) {
        showError('Only admin can add agents to groups');
        return;
    }
    // Reset target position if called directly from "Add Agent" button
    if (event && event.currentTarget && event.currentTarget.getAttribute && event.currentTarget.getAttribute('onclick') === 'openAddAgentModal()') {
        targetSlotPosition = null;
    }

    selectedAgents.clear();
    updateSelectedCount();
    
     // Update modal title
    const titleEl = document.querySelector('#addAgentModal .modal-title');
    if (titleEl) {
        if (targetSlotPosition) {
            titleEl.textContent = `Assign Agent to Position ${targetSlotPosition}`;
        } else {
            titleEl.innerHTML = '<i class="fas fa-plus-circle me-2"></i>Add Agent to Group';
        }
    }

    const modal = new bootstrap.Modal(document.getElementById('addAgentModal'));
    modal.show();
    
    // Load available agents
    const container = document.getElementById('availableAgentsContainer');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';
    
    await loadAllAgents();
    renderAvailableAgents();
}

function renderAvailableAgents() {
    const container = document.getElementById('availableAgentsContainer');
    
    // Filter out agents already in this group
    const groupAgentIds = new Set(groupAgents.map(a => a.agent_id));
    const availableAgents = allAgents.filter(a => !groupAgentIds.has(a.agent_id));
    
    if (availableAgents.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4 text-muted">
                <i class="fas fa-check-circle fa-2x mb-2"></i>
                <p class="mb-0">All agents are already in this group</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = availableAgents.map(agent => {
        const displayName = agent.display_name || agent.hostname || agent.agent_id;
        const statusInfo = getStatusInfo(agent.status);
        const currentGroup = agent.group_id ? 'In another group' : 'Unassigned';
        
        return `
            <div class="available-agent-item ${selectedAgents.has(agent.agent_id) ? 'selected' : ''}" 
                 data-agent-id="${agent.agent_id}"
                 data-name="${(displayName + ' ' + (agent.hostname || '')).toLowerCase()}"
                 data-ip="${(agent.ip_address || '').toLowerCase()}"
                 onclick="toggleAgentSelection('${agent.agent_id}')">
                <input type="checkbox" class="form-check-input" 
                       ${selectedAgents.has(agent.agent_id) ? 'checked' : ''}>
                <div class="flex-grow-1">
                    <div class="fw-semibold">${escapeHtml(displayName)}</div>
                    <small class="text-muted">
                        ${agent.ip_address || 'Unknown IP'} · 
                        <span class="status-badge ${statusInfo.class}" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;">
                            ${statusInfo.text}
                        </span> · 
                        ${currentGroup}
                    </small>
                </div>
            </div>
        `;
    }).join('');
}

function toggleAgentSelection(agentId) {
    if (targetSlotPosition !== null) {
        // Single selection mode for specific slot
        if (selectedAgents.has(agentId)) {
            selectedAgents.delete(agentId);
        } else {
            selectedAgents.clear();
            selectedAgents.add(agentId);
        }
        
        // Update all checkboxes
        document.querySelectorAll('.available-agent-item').forEach(item => {
            const id = item.dataset.agentId;
            const isSelected = selectedAgents.has(id);
            item.classList.toggle('selected', isSelected);
            item.querySelector('input[type="checkbox"]').checked = isSelected;
        });
    } else {
        // Multi-selection mode
        if (selectedAgents.has(agentId)) {
            selectedAgents.delete(agentId);
        } else {
            selectedAgents.add(agentId);
        }
        
        // Update UI
        const item = document.querySelector(`.available-agent-item[data-agent-id="${agentId}"]`);
        if (item) {
            item.classList.toggle('selected', selectedAgents.has(agentId));
            item.querySelector('input[type="checkbox"]').checked = selectedAgents.has(agentId);
        }
    }
    
    updateSelectedCount();
}

function updateSelectedCount() {
    const count = selectedAgents.size;
    document.getElementById('selectedCount').textContent = count;
    document.getElementById('confirmAddAgents').disabled = count === 0;
}

function filterAvailableAgents() {
    const searchTerm = document.getElementById('availableAgentSearch').value.toLowerCase();
    const items = document.querySelectorAll('.available-agent-item');
    
    items.forEach(item => {
        const name = item.dataset.name || '';
        const ip = item.dataset.ip || '';
        const matches = name.includes(searchTerm) || ip.includes(searchTerm);
        item.style.display = matches ? 'flex' : 'none';
    });
}

async function addSelectedAgents() {
    if (selectedAgents.size === 0) return;
    
    const btn = document.getElementById('confirmAddAgents');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Adding...';
    
    try {
        const promises = Array.from(selectedAgents).map(agentId =>
            SaintAPI.patch(`/api/agents/${agentId}/group`, { group_id: groupId })
        );

        await Promise.all(promises);

        // If adding to specific slot
        if (targetSlotPosition !== null && selectedAgents.size === 1) {
            const agentId = selectedAgents.values().next().value;
            await SaintAPI.patch(`/api/agents/${agentId}/position`, {
                position: targetSlotPosition,
            });
        }

        showSuccess(`Added ${selectedAgents.size} agent(s) to group`);
        bootstrap.Modal.getInstance(document.getElementById('addAgentModal')).hide();

        // Reload agents
        await loadGroupAgents();

    } catch (error) {
        console.error('Error adding agents:', error);
        showError('Failed to add some agents');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-plus me-1"></i>Add Selected (<span id="selectedCount">0</span>)';
    }
}

// ========================================
// AGENT ACTIONS
// ========================================

async function removeAgentFromGroup(agentId) {
    if (!(window.SAINT_AUTH && window.SAINT_AUTH.isAdmin)) {
        showError('Only admin can remove agents from groups');
        return;
    }
    const agent = groupAgents.find(a => a.agent_id === agentId);
    const displayName = agent?.display_name || agent?.hostname || agentId;
    
    if (!confirm(`Remove "${displayName}" from this group?\n\nThe agent will be moved to Pending.`)) {
        return;
    }
    
    try {
        // Get pending group ID
        const groupsData = await SaintAPI.get('/api/groups');
        const pendingGroup = groupsData.data?.find(g => g.is_system && g.name === 'pending');

        if (!pendingGroup) {
            throw new Error('Pending group not found');
        }

        await SaintAPI.patch(`/api/agents/${agentId}/group`, {
            group_id: pendingGroup._id,
        });

        showSuccess(`${displayName} removed from group`);
        await loadGroupAgents();

    } catch (error) {
        console.error('Error removing agent:', error);
        showError('Failed to remove agent from group');
    }
}

function viewAgentLogs(agentId) {
    window.location.href = `/logs?agent_id=${agentId}`;
}

function updateAgentStatus(agentId, status, data) {
    const agent = groupAgents.find(a => a.agent_id === agentId);
    if (agent) {
        agent.status = status;
        agent.last_heartbeat = data.last_heartbeat;
        
        if (currentView === 'map') {
            renderGroupMap(groupAgents);
        } else {
            renderGroupAgents(groupAgents);
        }
        updateStatistics();
    }
}

// ========================================
// FILTER & SEARCH
// ========================================

function filterGroupAgents() {
    const searchTerm = document.getElementById('agentSearch').value.toLowerCase();
    const statusFilter = document.getElementById('statusFilter').value;
    
    const items = document.querySelectorAll('.group-agent-item');
    
    items.forEach(item => {
        const name = item.dataset.name || '';
        const ip = item.dataset.ip || '';
        const status = item.dataset.status || '';
        
        const matchesSearch = name.includes(searchTerm) || ip.includes(searchTerm);
        const matchesStatus = !statusFilter || status === statusFilter;
        
        item.style.display = (matchesSearch && matchesStatus) ? 'flex' : 'none';
    });
}

// ========================================
// EDIT GROUP
// ========================================

function openEditGroupModal() {
    const modal = new bootstrap.Modal(document.getElementById('editGroupModal'));
    modal.show();
}

async function saveGroupChanges() {
    const name = document.getElementById('editGroupName').value.trim();
    const description = document.getElementById('editGroupDescription').value.trim();
    
    if (!name) {
        showError('Group name is required');
        return;
    }
    
    try {
        const result = await SaintAPI.patch(`/api/groups/${groupId}`, {
            name,
            description,
        });

        if (!result || !result.success) {
            throw new Error((result && result.error) || 'Failed to update group');
        }

        // Update page
        document.getElementById('groupName').textContent = name;
        document.getElementById('groupDescription').textContent = description || 'No description';

        bootstrap.Modal.getInstance(document.getElementById('editGroupModal')).hide();
        showSuccess('Group updated successfully');

    } catch (error) {
        const msg = (error && error.body && (error.body.error || error.body.message)) || error.message;
        console.error('Error updating group:', error);
        showError(msg || 'Failed to update group');
    }
}

// ========================================
// UTILITIES
// ========================================

function getStatusInfo(status) {
    switch (status) {
        case 'active':
            return { class: 'active', text: 'Active' };
        case 'inactive':
            return { class: 'inactive', text: 'Inactive' };
        case 'offline':
            return { class: 'offline', text: 'Offline' };
        default:
            return { class: 'offline', text: 'Unknown' };
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'Never';
    // Delegate to SaintDate so this page renders identical timestamps to
    // every other admin page (vi-VN, dd/MM/yyyy HH:mm). The local impl used
    // to call ``toLocaleString()`` with no args, which silently varies by
    // browser locale.
    if (window.SaintDate) {
        const formatted = window.SaintDate.formatVN(timestamp);
        return formatted || 'Invalid Date';
    }
    try {
        return new Date(timestamp).toLocaleString();
    } catch {
        return 'Invalid Date';
    }
}

// Delegate to the shared helper so XSS-escape behavior is identical across
// admin pages (see server/views/static/js/core/utils.js).
const escapeHtml = (value) => window.SaintUtils.escapeHtml(value);

function showSuccess(message) {
    if (typeof showNotification === 'function') {
        showNotification('success', message);
    } else {
        alert(message);
    }
}

function showError(message) {
    if (typeof showNotification === 'function') {
        showNotification('danger', message);
    } else {
        alert('Error: ' + message);
    }
}

// ========================================
// MAP VIEW & DRAG DROP
// ========================================

let targetSlotPosition = null;
let layoutSaveTimer = null;

function switchView(mode) {
    currentView = mode;
    const listContainer = document.getElementById('groupAgentsContainer');
    const mapWrapper = document.getElementById('groupMapWrapper');
    const filterParams = document.getElementById('listFilterParams');
    
    if (mode === 'map') {
        listContainer.style.display = 'none';
        mapWrapper.style.display = 'block';
        if (filterParams) filterParams.style.display = 'none';
        renderGroupMap(groupAgents);
    } else {
        listContainer.style.display = 'block';
        mapWrapper.style.display = 'none';
        if (filterParams) filterParams.style.display = 'block';
        renderGroupAgents(groupAgents); // Re-render to ensure latest state
    }
}

function updateGridLayout() {
    renderGroupMap(groupAgents);
    
    // Save to server with debounce
    if (layoutSaveTimer) clearTimeout(layoutSaveTimer);
    layoutSaveTimer = setTimeout(() => {
        saveGroupLayout();
    }, 1000);
}

async function saveGroupLayout() {
    let rows = parseInt(document.getElementById('gridRows').value);
    let cols = parseInt(document.getElementById('gridCols').value);
    
    if (!rows || rows < 1) rows = 1;
    if (!cols || cols < 1) cols = 1;

    try {
        await SaintAPI.patch(`/api/groups/${groupId}`, {
            layout: { rows: rows, cols: cols },
        });
    } catch (e) {
        console.error("Error saving room layout:", e);
    }
}

function renderGroupMap(agents) {
    const mapContainer = document.getElementById('groupMapContainer');
    const unassignedContainer = document.getElementById('unassignedGrid');
    
    // Get Grid Configuration (limit processing if value is invalid)
    let rows = parseInt(document.getElementById('gridRows').value);
    let cols = parseInt(document.getElementById('gridCols').value);
    
    if (!rows || rows < 1) rows = 1;
    if (!cols || cols < 1) cols = 1;
    
    // Create Layout: Single flexible grid
    // Use CSS Grid in inline style for dynamic rows/cols
    const gridStyle = `display: grid; grid-template-columns: repeat(${cols}, 1fr); gap: 10px; padding: 10px;`;
    
    let html = `<div class="classroom-layout" style="${gridStyle}">`;
    
    const totalSlots = rows * cols;
    
    // Calculate size estimate (optional optimisation)
    
    for (let i = 0; i < totalSlots; i++) {
        const pos = i + 1; 
        html += renderSlot(pos, agents);
    }
    
    html += '</div>'; // End layout
    
    mapContainer.innerHTML = html;
    
    // Render Unassigned
    // Filter agents that have no position OR have position > totalSlots
    const unassigned = agents.filter(a => !a.position || a.position < 1 || a.position > totalSlots);
    
    // We sort unassigned by status (active first) then name
    unassigned.sort((a, b) => {
        if (a.status === 'active' && b.status !== 'active') return -1;
        if (a.status !== 'active' && b.status === 'active') return 1;
        return (a.display_name || '').localeCompare(b.display_name || '');
    });
    
    if (unassigned.length > 0) {
        unassignedContainer.innerHTML = unassigned.map(agent => renderDraggableCard(agent)).join('');
    } else {
        unassignedContainer.innerHTML = '<div class="text-muted p-3 w-100 text-center small" style="grid-column: 1 / -1;">All agents assigned to positions</div>';
    }
}

function renderSlot(pos, agents) {
    const agent = agents.find(a => a.position === pos);
    let content = '';
    
    if (agent) {
        content = renderDraggableCard(agent, true);
        return `
            <div class="device-slot occupied" id="slot-${pos}" 
                 ondrop="drop(event, ${pos})" 
                 ondragover="allowDrop(event)">
                 <div class="position-badge">${pos}</div>
                 ${content}
            </div>
        `;
    } else {
        // Empty slot - clickable to map agent
        return `
            <div class="device-slot empty" id="slot-${pos}" 
                 ondrop="drop(event, ${pos})" 
                 ondragover="allowDrop(event)"
                 onclick="openAssignPositionModal(${pos})"
                 title="Click to assign agent">
                 <div class="position-badge">${pos}</div>
                 <div class="slot-placeholder">
                    <i class="fas fa-plus"></i>
                 </div>
            </div>
        `;
    }
}

// ========================================
// ASSIGN POSITION MODAL
// ========================================

function openAssignPositionModal(pos) {
    targetSlotPosition = pos;
    const modalTitle = document.querySelector('#assignPositionModal .modal-title');
    if (modalTitle) modalTitle.textContent = `Assign Agent to Position ${pos}`;
    
    // Populate list
    // Filter agents in group that DO NOT have a position (or position is invalid/cleared)
    // Also include agents that might have high positions if they are considered unassigned in pool
    // But conceptually, we just want agents who are currently "Unassigned"
    
    // We can also allow moving agents? For simplicity, just unassigned ones first.
    // If user wants to swap, they can drag drop.
    const unassigned = groupAgents.filter(a => !a.position || a.position < 1);
    
    renderUnassignedAgentsList(unassigned);
    
    const modal = new bootstrap.Modal(document.getElementById('assignPositionModal'));
    modal.show();
}

function renderUnassignedAgentsList(agents) {
    const container = document.getElementById('unassignedAgentsList');
    if (!container) return;
    
    if (agents.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4 text-muted">
                <p class="mb-2">No unassigned agents found</p>
                <small>Use "Add Agent" to bring new agents into the group first.</small>
            </div>
        `;
        return;
    }
    
    container.innerHTML = agents.map(agent => {
        const displayName = agent.display_name || agent.hostname || agent.agent_id;
        const statusInfo = getStatusInfo(agent.status);
        
        return `
            <button type="button" class="list-group-item list-group-item-action d-flex align-items-center gap-3 unassigned-list-item"
                    data-search="${(displayName + ' ' + (agent.ip_address || '')).toLowerCase()}"
                    onclick="assignAgentToPosition('${agent.agent_id}')">
                <div class="agent-avatar small" style="width: 32px; height: 32px; font-size: 0.8rem;">
                    <i class="fas fa-desktop"></i>
                </div>
                <div class="flex-grow-1 text-start">
                    <div class="fw-semibold small">${escapeHtml(displayName)}</div>
                    <div class="text-muted extra-small" style="font-size: 0.75rem;">
                        ${agent.ip_address || 'Unknown IP'}
                    </div>
                </div>
                <span class="badge ${getStatusBadgeClass(agent.status)} rounded-pill">
                    ${statusInfo.text}
                </span>
            </button>
        `;
    }).join('');
}

function getStatusBadgeClass(status) {
    switch(status) {
        case 'active': return 'bg-success';
        case 'inactive': return 'bg-warning text-dark';
        case 'offline': return 'bg-danger';
        default: return 'bg-secondary';
    }
}

function filterUnassignedAgentsList() {
    const term = document.getElementById('unassignedAgentSearch').value.toLowerCase();
    const items = document.querySelectorAll('.unassigned-list-item');
    items.forEach(item => {
        const text = item.getAttribute('data-search') || '';
        item.style.display = text.includes(term) ? 'flex' : 'none';
    });
}

async function assignAgentToPosition(agentId) {
    if (targetSlotPosition === null) return;
    
    const btn = event.currentTarget;
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<div class="spinner-border spinner-border-sm text-primary me-2"></div> Assigning...';
    btn.disabled = true;

    try {
        await updateAgentPosition(agentId, targetSlotPosition);
        
        // Close modal
        const modalEl = document.getElementById('assignPositionModal');
        const modal = bootstrap.Modal.getInstance(modalEl);
        modal.hide();
        
        showSuccess('Agent assigned successfully');
    } catch (error) {
        console.error('Error assigning agent:', error);
        btn.innerHTML = originalContent;
        btn.disabled = false;
        showError('Failed to assign agent');
    }
}

function renderDraggableCard(agent, isCompact=false) {
    const statusClass = `status-${agent.status || 'offline'}`;
    const displayName = agent.display_name || agent.hostname;
    const shortIp = agent.ip_address || '---';

    // Policy overlay
    const policy = agentPolicies[agent.agent_id];
    const policyMode = policy?.override_mode || 'none';
    const policyClass = policyMode !== 'none' ? ` policy-${policyMode}` : '';
    let policyBadgeHtml = '';
    if (policyMode === 'isolate') {
        policyBadgeHtml = '<span class="policy-badge policy-badge-isolate" title="Network Isolated"><i class="fas fa-ban"></i></span>';
    } else if (policyMode === 'custom_whitelist') {
        policyBadgeHtml = '<span class="policy-badge policy-badge-custom" title="Custom Whitelist"><i class="fas fa-list-alt"></i></span>';
    }

    // Right-click handler for context menu
    const ctxHandler = `oncontextmenu="showAgentContextMenu(event, '${agent.agent_id}')"`;

    if (isCompact) {
         return `
            <div class="device-card ${statusClass}${policyClass}"
                 id="card-${agent.agent_id}"
                 draggable="true"
                 data-agent-id="${agent.agent_id}"
                 ondragstart="drag(event, '${agent.agent_id}')"
                 ${ctxHandler}
                 title="${escapeHtml(displayName)}">
                ${policyBadgeHtml}
                <div class="device-icon">
                    <i class="fas fa-desktop"></i>
                </div>
                <div class="device-info">
                    <span class="device-ip">${escapeHtml(shortIp)}</span>
                </div>
            </div>
        `;
    }

    return `
        <div class="device-card ${statusClass}${policyClass}"
             id="card-${agent.agent_id}"
             draggable="true"
             style="width: 100px; height: 100px;"
             data-agent-id="${agent.agent_id}"
             ondragstart="drag(event, '${agent.agent_id}')"
             ${ctxHandler}>
            ${policyBadgeHtml}
            <div class="device-icon">
                <i class="fas fa-desktop"></i>
            </div>
            <div class="device-info">
                <div class="fw-bold small text-truncate" style="max-width: 90px;" title="${displayName}">${displayName}</div>
                <div class="small text-muted">${shortIp}</div>
            </div>
        </div>
    `;
}

// Drag and Drop Handlers

function allowDrop(ev) {
    if (!(window.SAINT_AUTH && window.SAINT_AUTH.isAdmin)) return;
    ev.preventDefault();
    const slot = ev.currentTarget;
    if (slot && !slot.classList.contains('drag-over')) {
        slot.classList.add('drag-over');
    }
}

function drag(ev, agentId) {
    if (!(window.SAINT_AUTH && window.SAINT_AUTH.isAdmin)) { ev.preventDefault(); return; }
    ev.dataTransfer.setData("agent_id", agentId);
    ev.dataTransfer.effectAllowed = 'move';
    const card = ev.currentTarget.closest('.device-card');
    if (card) {
        setTimeout(() => card.classList.add('is-dragging'), 0);
    }
}

function drop(ev, pos) {
    ev.preventDefault();
    const slot = ev.currentTarget;
    slot.classList.remove('drag-over');
    
    const agentId = ev.dataTransfer.getData("agent_id");
    if (!agentId) return;
    
    const card = document.getElementById(`card-${agentId}`);
    if (card) card.classList.remove('is-dragging');

    updateAgentPosition(agentId, pos);
}

function dropToUnassigned(ev) {
    ev.preventDefault();
    ev.currentTarget.classList.remove('drag-over');
    
    const agentId = ev.dataTransfer.getData("agent_id");
    if (!agentId) return;
    
    const card = document.getElementById(`card-${agentId}`);
    if (card) card.classList.remove('is-dragging');
    
    updateAgentPosition(agentId, null);
}

// Remove drag-over class when drag leaves
document.addEventListener('DOMContentLoaded', function() {
    document.addEventListener('dragleave', function(ev) {
        if (ev.target.classList.contains('device-slot')) {
            ev.target.classList.remove('drag-over');
        }
    });
    
    document.addEventListener('dragend', function(ev) {
        // Clean up all drag-over states
        document.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
        document.querySelectorAll('.is-dragging').forEach(el => el.classList.remove('is-dragging'));
    });
});

async function updateAgentPosition(agentId, position) {
    try {
        await SaintAPI.patch(`/api/agents/${agentId}/position`, { position });

        // Update local state
        const agent = groupAgents.find(a => a.agent_id === agentId);
        if (agent) {
            agent.position = position;
        }

        if (position !== null) {
            const collidingAgent = groupAgents.find(a => a.position === position && a.agent_id !== agentId);
            if (collidingAgent) {
                collidingAgent.position = null;
            }
        }

        renderGroupMap(groupAgents);

    } catch (error) {
        console.error('Error updating position:', error);
        alert('Failed to update position');
    }
}

// ========================================
// AGENT POLICY - Context Menu & Actions
// ========================================

function showAgentContextMenu(event, agentId) {
    event.preventDefault();
    event.stopPropagation();

    ctxTargetAgentId = agentId;
    const agent = groupAgents.find(a => a.agent_id === agentId);
    const displayName = agent?.display_name || agent?.hostname || agentId;

    // Update header
    document.getElementById('ctxAgentName').textContent = displayName;

    // Position menu at cursor
    const menu = document.getElementById('agentContextMenu');
    menu.style.display = 'block';

    // Ensure menu stays within viewport
    const menuRect = menu.getBoundingClientRect();
    let x = event.clientX;
    let y = event.clientY;
    if (x + menuRect.width > window.innerWidth) x = window.innerWidth - menuRect.width - 8;
    if (y + menuRect.height > window.innerHeight) y = window.innerHeight - menuRect.height - 8;

    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
}

// Close context menu on click anywhere
document.addEventListener('click', () => {
    document.getElementById('agentContextMenu').style.display = 'none';
});
document.addEventListener('contextmenu', (e) => {
    // Close old menu if clicking outside device cards
    if (!e.target.closest('.device-card')) {
        document.getElementById('agentContextMenu').style.display = 'none';
    }
});

// ── Set Policy (none / isolate) ──

function ctxSetPolicy(mode) {
    document.getElementById('agentContextMenu').style.display = 'none';

    if (mode === 'none') {
        applyPolicy(ctxTargetAgentId, 'none');
        return;
    }

    if (mode === 'isolate') {
        // Open isolate confirm modal
        const agent = groupAgents.find(a => a.agent_id === ctxTargetAgentId);
        document.getElementById('isolateAgentName').textContent =
            agent?.display_name || agent?.hostname || ctxTargetAgentId;
        document.getElementById('isolateReason').value = '';

        const modal = new bootstrap.Modal(document.getElementById('isolateConfirmModal'));
        modal.show();

        // Wire confirm button (remove old listener first)
        const btn = document.getElementById('confirmIsolateBtn');
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
        newBtn.addEventListener('click', async () => {
            newBtn.disabled = true;
            newBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Processing...';

            const reason = document.getElementById('isolateReason').value.trim();
            const durVal = document.getElementById('isolateDuration').value;
            const duration = durVal ? parseInt(durVal) : null;

            await applyPolicy(ctxTargetAgentId, 'isolate', reason, duration);
            bootstrap.Modal.getInstance(document.getElementById('isolateConfirmModal')).hide();
            newBtn.disabled = false;
            newBtn.innerHTML = '<i class="fas fa-ban me-1"></i>Isolate';
        });
    }
}

// ── Custom Whitelist Modal ──

function ctxOpenCustomWhitelist() {
    document.getElementById('agentContextMenu').style.display = 'none';

    const agent = groupAgents.find(a => a.agent_id === ctxTargetAgentId);
    document.getElementById('customWlAgentName').textContent =
        agent?.display_name || agent?.hostname || ctxTargetAgentId;

    // Pre-fill from existing policy if any
    const policy = agentPolicies[ctxTargetAgentId];
    if (policy?.override_mode === 'custom_whitelist' && policy?.custom_whitelist?.length) {
        customWlDomains = policy.custom_whitelist.map(e => e.domain || e);
    } else {
        customWlDomains = [];
    }

    document.getElementById('customWlReason').value = policy?.reason || '';
    document.getElementById('customWlDomainInput').value = '';
    renderCustomWlDomains();

    const modal = new bootstrap.Modal(document.getElementById('customWhitelistModal'));
    modal.show();

    // Wire confirm button
    const btn = document.getElementById('confirmCustomWlBtn');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    newBtn.addEventListener('click', async () => {
        if (customWlDomains.length === 0) {
            showError('Add at least 1 domain');
            return;
        }
        newBtn.disabled = true;
        newBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Processing...';

        const reason = document.getElementById('customWlReason').value.trim();
        const durVal = document.getElementById('customWlDuration').value;
        const duration = durVal ? parseInt(durVal) : null;
        const entries = customWlDomains.map(d => ({ domain: d }));

        await applyPolicy(ctxTargetAgentId, 'custom_whitelist', reason, duration, entries);
        bootstrap.Modal.getInstance(document.getElementById('customWhitelistModal')).hide();
        newBtn.disabled = false;
        newBtn.innerHTML = '<i class="fas fa-check me-1"></i>Apply';
    });
}

function addCustomWlDomain() {
    const input = document.getElementById('customWlDomainInput');
    const domain = input.value.trim().toLowerCase();
    if (!domain) return;
    if (customWlDomains.includes(domain)) {
        input.value = '';
        return;
    }
    customWlDomains.push(domain);
    input.value = '';
    renderCustomWlDomains();
    input.focus();
}

// Allow Enter key to add domain
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('customWlDomainInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); addCustomWlDomain(); }
    });
});

function removeCustomWlDomain(domain) {
    customWlDomains = customWlDomains.filter(d => d !== domain);
    renderCustomWlDomains();
}

function renderCustomWlDomains() {
    const container = document.getElementById('customWlDomainList');
    if (customWlDomains.length === 0) {
        container.innerHTML = '<div class="custom-wl-empty"><i class="fas fa-inbox me-1"></i>No domains yet</div>';
        return;
    }
    container.innerHTML = customWlDomains.map(d => `
        <div class="custom-wl-domain-item">
            <span><i class="fas fa-globe text-primary me-2"></i>${escapeHtml(d)}</span>
            <button class="btn-remove" onclick="removeCustomWlDomain('${escapeHtml(d)}')" title="Xóa">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `).join('');
}

// ── View Policy Info ──

async function ctxViewPolicy() {
    document.getElementById('agentContextMenu').style.display = 'none';

    const agent = groupAgents.find(a => a.agent_id === ctxTargetAgentId);
    document.getElementById('policyInfoAgentName').textContent =
        agent?.display_name || agent?.hostname || ctxTargetAgentId;

    const body = document.getElementById('policyInfoBody');
    body.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-primary"></div></div>';

    const modal = new bootstrap.Modal(document.getElementById('policyInfoModal'));
    modal.show();

    try {
        const result = await SaintAPI.get(`/api/agents/${ctxTargetAgentId}/policy`);
        const p = result.data || {};

        const modeLabels = {
            none: '<span class="badge bg-success">Normal</span>',
            isolate: '<span class="badge bg-danger">Isolated</span>',
            custom_whitelist: '<span class="badge bg-warning text-dark">Custom Whitelist</span>',
        };

        let html = `
            <div class="mb-2"><strong>Mode:</strong> ${modeLabels[p.override_mode] || modeLabels.none}</div>
        `;
        if (p.reason) html += `<div class="mb-2"><strong>Reason:</strong> ${escapeHtml(p.reason)}</div>`;
        if (p.applied_by_username) html += `<div class="mb-2"><strong>Applied by:</strong> ${escapeHtml(p.applied_by_username)}</div>`;
        if (p.expires_at) html += `<div class="mb-2"><strong>Expires:</strong> ${formatTimestamp(p.expires_at)}</div>`;
        if (p.updated_at) html += `<div class="mb-2"><strong>Updated:</strong> ${formatTimestamp(p.updated_at)}</div>`;

        if (p.override_mode === 'custom_whitelist' && p.custom_whitelist?.length) {
            html += `<div class="mt-2"><strong>Domains (${p.custom_whitelist.length}):</strong>
                <ul class="list-unstyled mb-0 mt-1">
                    ${p.custom_whitelist.map(e => `<li class="small"><i class="fas fa-globe text-primary me-1"></i>${escapeHtml(e.domain || e)}</li>`).join('')}
                </ul>
            </div>`;
        }

        body.innerHTML = html;
    } catch (e) {
        body.innerHTML = '<div class="text-danger small">Failed to load policy</div>';
    }
}

// ── Core API call ──

async function applyPolicy(agentId, mode, reason = '', durationMinutes = null, customWhitelist = null) {
    try {
        const body = { mode };
        if (reason) body.reason = reason;
        if (durationMinutes) body.duration_minutes = durationMinutes;
        if (customWhitelist) body.custom_whitelist = customWhitelist;

        const result = await SaintAPI.patch(`/api/agents/${agentId}/policy`, body);

        if (!result || !result.success) {
            throw new Error((result && result.error) || 'Failed to set policy');
        }

        // Update local cache
        agentPolicies[agentId] = result.data;

        // Re-render
        if (currentView === 'map') {
            renderGroupMap(groupAgents);
        } else {
            renderGroupAgents(groupAgents);
        }

        const modeMessages = {
            none: 'Unblocked - back to normal',
            isolate: 'Network isolated',
            custom_whitelist: 'Custom whitelist applied',
        };
        showSuccess(modeMessages[mode] || 'Policy updated');

    } catch (error) {
        console.error('Error setting policy:', error);
        showError(error.message || 'Cannot update policy');
    }
}

// ========================================
// INLINE WHITELIST EDITOR
// ========================================

// Group whitelist data for whitelist editor
let wlGroupData = null;

/**
 * Extract whitelist rows from the tolerant API shapes used across the app.
 */
function wlExtractItems(data) {
    if (!data) return [];
    if (Array.isArray(data.items)) return data.items;
    if (Array.isArray(data.domains)) return data.domains;
    if (Array.isArray(data.whitelist)) return data.whitelist;
    if (data.data && data.data !== data) return wlExtractItems(data.data);
    if (Array.isArray(data)) return data;
    return [];
}

function wlEntryValue(entry) {
    return typeof entry === 'string'
        ? entry
        : (entry?.value || entry?.domain || '');
}

function wlToEntry(raw, index) {
    const val = wlEntryValue(raw);
    const type = typeof raw === 'string' ? 'domain' : (raw.type || 'domain');
    const category = typeof raw === 'string' ? 'general' : (raw.category || 'general');
    const priority = typeof raw === 'string' ? 'normal' : (raw.priority || 'normal');
    const scope = typeof raw === 'string'
        ? 'group'
        : (raw.scope || raw._scope || (raw.group_id ? 'group' : 'group'));
    const fallbackId = `group::${groupId}::${type}::${val}`;
    const entryId = typeof raw === 'string'
        ? fallbackId
        : (raw._id || raw.id || fallbackId);

    return {
        _id: entryId,
        id: entryId,
        value: val,
        type: type,
        category: category,
        priority: priority,
        is_active: typeof raw === 'string' ? true : raw.is_active !== false,
        active: typeof raw === 'string' ? true : raw.active !== false,
        _scope: scope,
        scope: scope,
        group_id: typeof raw === 'string' ? groupId : (raw.group_id || groupId),
        _index: index,
    };
}

function wlSetCounts(count) {
    const countEl = document.getElementById('wlCount');
    const totalEl = document.getElementById('wlTotalCount');
    const heroCountEl = document.getElementById('whitelistCount');
    if (countEl) countEl.textContent = count;
    if (totalEl) totalEl.textContent = count;
    if (heroCountEl) heroCountEl.textContent = count;
}

/**
 * Load whitelist entries for this group from the unified whitelist API.
 */
async function wlLoadEntries() {
    const container = document.getElementById('wlDomainList');
    if (!container) return;

    try {
        const [groupResponse, whitelistResponse] = await Promise.all([
            SaintAPI.get(`/api/groups/${groupId}`),
            SaintAPI.get(`/api/whitelist?scope=group&group_id=${encodeURIComponent(groupId)}&limit=1000`),
        ]);

        if (!groupResponse.success || !whitelistResponse.success) {
            container.innerHTML = '<div class="wl-empty-state"><p>Error loading whitelist</p></div>';
            return;
        }

        wlGroupData = groupResponse.data || {};

        // First-class group whitelist entries live in `/api/whitelist`.
        // Legacy groups may still only have `group.whitelist[]`; keep that
        // fallback so old demo data remains visible.
        let groupEntries = wlExtractItems(whitelistResponse)
            .filter(entry => String(entry.group_id || groupId) === String(groupId))
            .map(wlToEntry)
            .filter(entry => entry.value);

        if (groupEntries.length === 0 && Array.isArray(wlGroupData.whitelist)) {
            groupEntries = wlGroupData.whitelist
                .map(wlToEntry)
                .filter(entry => entry.value);
        }

        wlGroupData.whitelist = groupEntries;

        wlAllEntries = groupEntries;
        wlEntries = [...wlAllEntries];

        // Update counters
        const versionEl = document.getElementById('wlVersion');
        wlSetCounts(groupEntries.length);
        if (versionEl) versionEl.textContent = wlGroupData.whitelist_version || 1;

        wlRenderList();
        wpUpdateBanner();
    } catch (err) {
        console.error('wlLoadEntries error:', err);
        container.innerHTML = '<div class="wl-empty-state"><p>Connection error</p></div>';
    }
}

/**
 * Render the filtered whitelist entries
 */
function wlRenderList() {
    const container = document.getElementById('wlDomainList');
    if (!container) return;

    if (wlEntries.length === 0) {
        container.innerHTML = `
            <div class="wl-empty-state">
                <i class="fas fa-shield-alt d-block"></i>
                <p>No domains found${wlAllEntries.length > 0 ? ' matching filter' : ''}</p>
            </div>`;
        return;
    }

    const html = wlEntries.map(entry => {
        const val = entry.value || entry.domain || '';
        const type = entry.type || 'domain';
        const category = entry.category || '';
        const isActive = entry.is_active !== false;
        const priority = entry.priority || 'normal';
        const scope = entry._scope || 'group';
        const entryId = entry._id || entry.id || '';
        const isGlobal = scope === 'global';

        // Icon by type
        let iconClass = 'fas fa-globe text-primary';
        if (type === 'ip') iconClass = 'fas fa-network-wired text-success';
        else if (type === 'url') iconClass = 'fas fa-link text-info';

        // Category badge
        let catBadge = '';
        if (category && category !== 'general' && category !== 'uncategorized') {
            catBadge = `<span class="badge bg-primary-subtle text-primary">${wlEscapeHtml(category)}</span>`;
        }

        // Scope badge
        const scopeBadge = isGlobal
            ? '<span class="badge bg-secondary">global</span>'
            : '<span class="badge bg-success-subtle text-success">group</span>';

        // Priority star
        const star = priority === 'high' ? '<i class="fas fa-star wl-priority-star" title="High priority"></i>' : '';

        // Delete button - use the whitelist entry id from the management API.
        const isAdminUser = window.SAINT_AUTH && window.SAINT_AUTH.isAdmin;
        const entryIdArg = encodeURIComponent(String(entryId));
        const deleteBtn = (isGlobal || !isAdminUser || !entryId)
            ? ''
            : `<div class="wl-actions">
                <button class="btn btn-outline-danger btn-sm" onclick="wlDeleteEntry(decodeURIComponent('${entryIdArg}'))" title="Delete">
                    <i class="fas fa-trash-alt"></i>
                </button>
               </div>`;

        return `
            <div class="wl-entry" data-entry-id="${wlEscapeHtml(entryId)}" data-scope="${wlEscapeHtml(scope)}">
                <div class="wl-entry-info">
                    <div class="wl-entry-icon"><i class="${iconClass}"></i></div>
                    <div class="wl-entry-text">
                        <div class="wl-entry-value">${wlEscapeHtml(val)}</div>
                        <div class="wl-entry-badges">
                            <span class="badge bg-light text-secondary">${wlEscapeHtml(type)}</span>
                            ${catBadge}
                            ${scopeBadge}
                        </div>
                    </div>
                    ${star}
                </div>
                ${deleteBtn}
            </div>`;
    }).join('');

    container.innerHTML = html;
}

/**
 * Filter visible entries by search text and type
 */
function wlFilterList() {
    const search = (document.getElementById('wlSearch')?.value || '').toLowerCase().trim();
    const typeFilter = document.getElementById('wlFilterType')?.value || '';

    wlEntries = wlAllEntries.filter(entry => {
        const val = (entry.value || entry.domain || '').toLowerCase();
        const type = entry.type || 'domain';

        if (search && !val.includes(search)) return false;
        if (typeFilter && type !== typeFilter) return false;
        return true;
    });

    wlRenderList();
}

/**
 * Add a new whitelist entry (supports comma-separated bulk)
 */
async function wlAddEntry() {
    const input = document.getElementById('wlNewValue');
    const typeSelect = document.getElementById('wlNewType');
    const btn = document.getElementById('wlAddBtn');
    if (!input || !wlGroupData) return;

    const raw = input.value.trim();
    if (!raw) { input.focus(); return; }

    // Split by comma, newline, or space (for bulk)
    const values = raw.split(/[,\n\s]+/).map(v => v.trim().toLowerCase()).filter(Boolean);
    if (values.length === 0) return;

    const type = typeSelect?.value || 'domain';

    let addedCount = 0;
    const items = [];
    for (const val of values) {
        const exists = wlAllEntries.some(d => wlEntryValue(d).toLowerCase() === val);
        if (!exists) {
            items.push({
                value: val,
                type: type,
                category: 'general',
                scope: 'group',
                group_id: groupId,
                is_active: true,
            });
            addedCount++;
        }
    }

    if (addedCount === 0) {
        showNotification('warning', 'All domains already exist');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

    try {
        const data = await SaintAPI.post('/api/whitelist/bulk', { items });

        if (data.success) {
            input.value = '';
            showNotification('success', `Added ${addedCount} domain(s)`);
            await wlLoadEntries();
        } else {
            showNotification('danger', data.error || 'Cannot add domain');
        }
    } catch (err) {
        console.error('wlAddEntry error:', err);
        showNotification('danger', 'Server connection error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-plus"></i>';
    }
}

/**
 * Delete a whitelist entry
 */
async function wlDeleteEntry(entryId) {
    if (!entryId || !wlGroupData) return;
    if (!confirm('Remove this domain from whitelist?')) return;

    const entry = wlAllEntries.find(item => String(item._id || item.id) === String(entryId));
    const removedVal = wlEntryValue(entry);

    try {
        const data = await SaintAPI.del(`/api/whitelist/${encodeURIComponent(entryId)}`);

        if (data.success) {
            showNotification('success', `Deleted "${removedVal}"`);
            await wlLoadEntries();
        } else {
            showNotification('danger', data.error || 'Cannot delete');
        }
    } catch (err) {
        console.error('wlDeleteEntry error:', err);
        showNotification('danger', 'Connection error');
    }
}

/**
 * Handle Enter key in the add input
 */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && e.target.id === 'wlNewValue') {
        e.preventDefault();
        wlAddEntry();
    }
});

// Whitelist editor + teacher modals used a separate name (``wlEscapeHtml``)
// for historical reasons. Keep the name so call sites in this file don't
// move, but route through the shared helper.
const wlEscapeHtml = (value) => window.SaintUtils.escapeHtml(value);

// ========================================
// WHITELIST PROFILES
// ========================================

async function wpLoadProfiles() {
    try {
        const data = await SaintAPI.get(`/api/groups/${groupId}/profiles`);
        if (!data.success) return;
        wpProfiles = data.data || [];
        wpRenderProfiles();
        wpUpdateBanner();
    } catch (e) {
        console.error('Failed to load profiles:', e);
    }
}

/**
 * Update the Firewall Status Banner based on current profile state
 */
function wpUpdateBanner() {
    const iconEl = document.getElementById('firewallBannerIcon');
    const titleEl = document.getElementById('firewallBannerTitle');
    const descEl = document.getElementById('firewallBannerDesc');
    if (!titleEl || !descEl) return;

    const activeProfile = wpProfiles.find(p => p.is_active);

    if (activeProfile) {
        // Teacher profile is active
        iconEl.style.background = '#fff3e0';
        iconEl.innerHTML = '<i class="fas fa-user-shield text-warning fa-lg"></i>';
        titleEl.innerHTML = `<span class="text-warning">Teacher Profile Active</span>`;
        descEl.innerHTML = `<i class="fas fa-play-circle me-1 text-warning"></i><strong>${wlEscapeHtml(activeProfile.name)}</strong> - ${wlEscapeHtml(activeProfile.teacher_username || '')} <span class="text-muted">(${(activeProfile.domains || []).length} domains)</span>`;
    } else {
        // Group base whitelist is in use
        const domainCount = wlGroupData ? (wlGroupData.whitelist || []).length : '...';
        iconEl.style.background = '#e8f5e9';
        iconEl.innerHTML = '<i class="fas fa-shield-alt text-success fa-lg"></i>';
        titleEl.innerHTML = `<span class="text-success">Group Whitelist</span>`;
        descEl.innerHTML = `<i class="fas fa-check-circle me-1 text-success"></i>Using Group Base Whitelist <span class="text-muted">(${domainCount} domains)</span>`;
    }
}

/**
 * Render Teacher Profiles as a table
 */
function wpRenderProfiles() {
    const container = document.getElementById('profilesList');
    const countEl = document.getElementById('profileCount');
    if (!container) return;

    const teacherProfiles = wpProfiles;
    if (countEl) countEl.textContent = teacherProfiles.length;

    if (teacherProfiles.length === 0) {
        container.innerHTML = '<div class="text-center py-3 text-muted small">No teacher profiles yet</div>';
        return;
    }

    const isAdmin = window.SAINT_AUTH && window.SAINT_AUTH.isAdmin;
    const currentUserId = window.SAINT_AUTH?.user?._id;

    let html = `
    <div class="table-responsive">
        <table class="table table-sm table-hover mb-0 align-middle">
            <thead class="table-light">
                <tr>
                    <th class="ps-3">Name</th>
                    <th>Owner</th>
                    <th class="text-center">Domains</th>
                    <th class="text-center">Status</th>
                    <th class="text-end pe-3">Actions</th>
                </tr>
            </thead>
            <tbody>`;

    for (const p of teacherProfiles) {
        const isActive = p.is_active;
        const domainCount = (p.domains || []).length;
        const isOwn = currentUserId && String(p.teacher_id) === String(currentUserId);
        const canManage = isOwn || isAdmin;

        const statusBadge = isActive
            ? '<span class="badge bg-success"><i class="fas fa-circle me-1" style="font-size:0.5rem;vertical-align:middle;"></i>Active</span>'
            : '<span class="badge bg-secondary"><i class="fas fa-circle me-1" style="font-size:0.5rem;vertical-align:middle;"></i>Off</span>';

        // Action buttons
        let actions = '';

        // Activate / Deactivate
        if (isActive) {
            actions += `<button class="btn btn-outline-warning btn-sm" onclick="wpDeactivate('${p._id}')" title="Deactivate profile"><i class="fas fa-pause"></i></button>`;
        } else {
            actions += `<button class="btn btn-outline-success btn-sm" onclick="wpActivate('${p._id}')" title="Activate"><i class="fas fa-play"></i></button>`;
        }

        // Edit Rules - inline modal editor
        if (canManage) {
            actions += ` <button class="btn btn-outline-primary btn-sm" onclick="wpOpenEditDomains('${p._id}')" title="Edit Rules"><i class="fas fa-edit"></i></button>`;
        }

        // Delete (only non-active, only owner/admin)
        if (canManage && !isActive) {
            actions += ` <button class="btn btn-outline-danger btn-sm" onclick="wpDeleteProfile('${p._id}')" title="Delete"><i class="fas fa-trash"></i></button>`;
        }

        html += `
            <tr class="${isActive ? 'table-success' : ''}">
                <td class="ps-3 fw-semibold small">${wlEscapeHtml(p.name)}</td>
                <td class="small text-muted">${wlEscapeHtml(p.teacher_username || '-')}</td>
                <td class="text-center"><span class="badge bg-light text-dark">${domainCount}</span></td>
                <td class="text-center">${statusBadge}</td>
                <td class="text-end pe-3">
                    <div class="btn-group btn-group-sm">${actions}</div>
                </td>
            </tr>`;
    }

    html += `</tbody></table></div>`;
    container.innerHTML = html;
}

async function wpActivate(profileId) {
    // Refresh from server to get fresh state before activating
    try {
        const freshData = await SaintAPI.get(`/api/groups/${groupId}/profiles`);
        if (freshData.success) {
            wpProfiles = freshData.data || [];
            wpRenderProfiles();
        }
    } catch (e) { /* proceed with cached state */ }

    const activeProfile = wpProfiles.find(p => p.is_active);
    if (activeProfile && activeProfile._id !== profileId) {
        const confirmed = confirm(
            `Profile "${activeProfile.name}" by ${activeProfile.teacher_username} is currently active.\n` +
            `Do you want to deactivate it and activate the new profile?`
        );
        if (!confirmed) return;
    }

    try {
        const data = await SaintAPI.post(`/api/groups/${groupId}/profiles/${profileId}/activate`);
        if (data.success) {
            await wpLoadProfiles();
            showNotification('success', 'Profile activated');
        } else {
            showNotification('danger', data.error || 'Failed');
        }
    } catch (e) {
        showNotification('danger', 'Error activating profile');
    }
}

async function wpDeactivate(profileId) {
    try {
        const data = await SaintAPI.post(`/api/groups/${groupId}/profiles/${profileId}/deactivate`);
        if (data.success) {
            await wpLoadProfiles();
            showNotification('warning', 'Profile deactivated - fallback to Default');
        } else {
            showNotification('danger', data.error || 'Failed');
        }
    } catch (e) {
        showNotification('danger', 'Error deactivating profile');
    }
}

function openCreateProfileModal() {
    document.getElementById('profileEditId').value = '';
    document.getElementById('profileName').value = '';
    document.getElementById('profileModalTitle').innerHTML = '<i class="fas fa-clipboard-list me-2"></i>New Whitelist Profile';
    new bootstrap.Modal(document.getElementById('profileModal')).show();
}

// wpEditProfile removed - replaced by wpOpenEditDomains() inline modal

/**
 * Save new profile (name only - domains managed on /whitelist page)
 */
async function saveProfile() {
    const name = document.getElementById('profileName').value.trim();
    if (!name) {
        showNotification('warning', 'Profile name cannot be empty');
        return;
    }

    const payload = { name, domains: [] };

    try {
        const data = await SaintAPI.post(`/api/groups/${groupId}/profiles`, payload);
        if (data.success) {
            bootstrap.Modal.getInstance(document.getElementById('profileModal'))?.hide();
            await wpLoadProfiles();
            showNotification('success', 'Profile created - use "Edit Rules" to add domains');
        } else {
            showNotification('danger', data.error || 'Failed');
        }
    } catch (e) {
        showNotification('danger', 'Error saving profile');
    }
}

async function wpDeleteProfile(profileId) {
    if (!confirm('Delete this profile?')) return;
    try {
        const data = await SaintAPI.del(`/api/groups/${groupId}/profiles/${profileId}`);
        if (data.success) {
            wpLoadProfiles();
            showNotification('success', 'Profile deleted');
        } else {
            showNotification('danger', data.error || 'Failed');
        }
    } catch (e) {
        showNotification('danger', 'Error deleting profile');
    }
}

// ========================================
// TEACHER ASSIGNMENT (Admin only)
// ========================================

async function wpLoadTeachers() {
    // Only load for admin
    if (!window.SAINT_AUTH || !window.SAINT_AUTH.isAdmin) return;

    try {
        // Get group data to find current teacher_ids
        const data = await SaintAPI.get(`/api/groups/${groupId}`);
        if (!data.success) return;

        const group = data.data;
        wpAssignedTeachers = (group.teacher_ids || []).map(String);
        wpRenderTeachersList(group);
    } catch (e) {
        console.error('Failed to load teachers:', e);
    }
}

async function wpRenderTeachersList(group) {
    const container = document.getElementById('teachersList');
    const countEl = document.getElementById('teacherCount');
    if (!container) return;

    const teacherIds = (group.teacher_ids || []).map(String);
    if (countEl) countEl.textContent = teacherIds.length;

    if (teacherIds.length === 0) {
        container.innerHTML = '<div class="text-center py-3 text-muted small">No teachers assigned</div>';
        return;
    }

    // Fetch user details for assigned teachers
    try {
        const data = await SaintAPI.get('/api/admin/users');
        if (!data.success) return;

        const allUsers = data.data?.users || data.data || [];
        const teachers = allUsers.filter(u =>
            u.role === 'teacher' && teacherIds.includes(String(u._id))
        );

        if (teachers.length === 0) {
            container.innerHTML = '<div class="text-center py-3 text-muted small">No teachers assigned</div>';
            return;
        }

        container.innerHTML = teachers.map(t => `
            <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                <div>
                    <i class="fas fa-user-tie me-2 text-success"></i>
                    <span class="fw-semibold">${wlEscapeHtml(t.username)}</span>
                    ${t.full_name ? `<small class="text-muted ms-1">(${wlEscapeHtml(t.full_name)})</small>` : ''}
                </div>
                <button class="btn btn-outline-danger btn-sm" onclick="wpRemoveTeacher('${t._id}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<div class="text-center py-3 text-muted small">Error loading teacher info</div>';
    }
}

async function openAssignTeacherModal() {
    const container = document.getElementById('allTeachersList');
    container.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-primary"></div></div>';
    new bootstrap.Modal(document.getElementById('assignTeacherModal')).show();

    try {
        const data = await SaintAPI.get('/api/admin/users');
        if (!data.success) return;

        const allUsers = data.data?.users || data.data || [];
        const teachers = allUsers.filter(u => u.role === 'teacher');
        if (teachers.length === 0) {
            container.innerHTML = '<div class="text-center py-3 text-muted">No teachers available</div>';
            return;
        }

        container.innerHTML = teachers.map(t => {
            const assigned = wpAssignedTeachers.includes(String(t._id));
            return `
            <label class="list-group-item d-flex align-items-center gap-2 py-2" style="cursor:pointer;">
                <input type="checkbox" class="form-check-input teacher-checkbox" value="${t._id}"
                       ${assigned ? 'checked' : ''}>
                <div>
                    <span class="fw-semibold">${wlEscapeHtml(t.username)}</span>
                    ${t.full_name ? `<small class="text-muted ms-1">(${wlEscapeHtml(t.full_name)})</small>` : ''}
                </div>
            </label>`;
        }).join('');
    } catch (e) {
        container.innerHTML = '<div class="text-center py-3 text-danger">Error loading teachers</div>';
    }
}

async function saveTeacherAssignments() {
    const checkboxes = document.querySelectorAll('#allTeachersList .teacher-checkbox');
    const selectedIds = [];
    checkboxes.forEach(cb => {
        if (cb.checked) selectedIds.push(cb.value);
    });

    try {
        const data = await SaintAPI.post(`/api/groups/${groupId}/teachers`, {
            teacher_ids: selectedIds,
        });
        if (data.success) {
            bootstrap.Modal.getInstance(document.getElementById('assignTeacherModal'))?.hide();
            wpAssignedTeachers = selectedIds;
            wpLoadTeachers();
            showNotification('success', 'Teachers updated');
        } else {
            showNotification('danger', data.error || 'Failed');
        }
    } catch (e) {
        showNotification('danger', 'Error saving teachers');
    }
}

async function wpRemoveTeacher(teacherId) {
    if (!confirm('Remove teacher from this group?')) return;
    const newIds = wpAssignedTeachers.filter(id => id !== String(teacherId));

    try {
        const data = await SaintAPI.post(`/api/groups/${groupId}/teachers`, {
            teacher_ids: newIds,
        });
        if (data.success) {
            wpAssignedTeachers = newIds;
            wpLoadTeachers();
            showNotification('success', 'Teacher removed');
        } else {
            showNotification('danger', data.error || 'Failed');
        }
    } catch (e) {
        showNotification('danger', 'Error removing teacher');
    }
}

// ========================================
// INLINE PROFILE DOMAIN EDITOR
// ========================================

let epdEditingProfile = null;   // profile object being edited
let epdDomains = [];            // local copy of domains for editing

function wpOpenEditDomains(profileId) {
    const profile = wpProfiles.find(p => p._id === profileId);
    if (!profile) {
        showNotification('danger', 'Profile not found');
        return;
    }

    epdEditingProfile = profile;
    epdDomains = JSON.parse(JSON.stringify(profile.domains || []));

    document.getElementById('epd-profileId').value = profileId;
    document.getElementById('epd-title').innerHTML =
        `<i class="fas fa-edit me-2"></i>Edit: ${wlEscapeHtml(profile.name)}`;
    document.getElementById('epd-profileName').textContent = profile.name;
    document.getElementById('epd-owner').textContent =
        profile.teacher_username ? `by ${profile.teacher_username}` : '';
    document.getElementById('epd-newValue').value = '';

    epdRenderDomains();
    new bootstrap.Modal(document.getElementById('editProfileDomainsModal')).show();
}

function epdRenderDomains() {
    const container = document.getElementById('epd-domainList');
    const countEl = document.getElementById('epd-count');
    if (countEl) countEl.textContent = epdDomains.length;

    if (epdDomains.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-3">No domains yet. Add some above.</div>';
        return;
    }

    container.innerHTML = epdDomains.map((d, i) => {
        const val = typeof d === 'string' ? d : (d.value || '');
        const type = typeof d === 'string' ? 'domain' : (d.type || 'domain');
        const typeBadge = type === 'ip' ? 'bg-warning text-dark' : type === 'url' ? 'bg-info text-white' : 'bg-primary';
        return `
            <div class="d-flex align-items-center justify-content-between py-1 px-2 border-bottom">
                <div class="d-flex align-items-center gap-2">
                    <span class="badge ${typeBadge}" style="font-size:0.65rem; min-width:50px;">${wlEscapeHtml(type)}</span>
                    <code class="small">${wlEscapeHtml(val)}</code>
                </div>
                <button class="btn btn-outline-danger btn-sm py-0 px-1" onclick="wpRemoveDomainFromProfile(${i})" title="Remove">
                    <i class="fas fa-times" style="font-size:0.7rem;"></i>
                </button>
            </div>`;
    }).join('');
}

function wpAddDomainToProfile() {
    const input = document.getElementById('epd-newValue');
    const typeSelect = document.getElementById('epd-newType');
    const raw = input.value.trim();
    if (!raw) { input.focus(); return; }

    const type = typeSelect?.value || 'domain';
    const values = raw.split(/[,\n\s]+/).map(v => v.trim().toLowerCase()).filter(Boolean);
    let addedCount = 0;

    for (const val of values) {
        const exists = epdDomains.some(d => {
            const dVal = typeof d === 'string' ? d : d.value;
            return dVal === val;
        });
        if (!exists) {
            epdDomains.push({ value: val, type: type });
            addedCount++;
        }
    }

    if (addedCount === 0) {
        showNotification('warning', 'All domains already exist');
        return;
    }

    input.value = '';
    epdRenderDomains();
}

function wpRemoveDomainFromProfile(index) {
    epdDomains.splice(index, 1);
    epdRenderDomains();
}

async function wpSaveProfileDomains() {
    if (!epdEditingProfile) return;
    const profileId = epdEditingProfile._id;

    try {
        const data = await SaintAPI.patch(
            `/api/groups/${groupId}/profiles/${profileId}`,
            { domains: epdDomains },
        );

        if (data.success) {
            bootstrap.Modal.getInstance(document.getElementById('editProfileDomainsModal'))?.hide();
            showNotification('success', `Saved ${epdDomains.length} domain(s)`);
            await wpLoadProfiles();
        } else {
            showNotification('danger', data.error || 'Failed to save');
        }
    } catch (e) {
        console.error('wpSaveProfileDomains error:', e);
        showNotification('danger', 'Server connection error');
    }
}
