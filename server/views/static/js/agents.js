let agentsData = [];

/**
 * Parse timestamp with Vietnam timezone support
 */
function parseTimestampCorrectly(timestamp) {
    if (!timestamp) return null;
    
    try {
        if (timestamp instanceof Date) {
            return timestamp;
        }

        if (typeof timestamp === 'number') {
            return new Date(timestamp);
        } 
        const normalized = String(timestamp).trim();

        // If the timestamp already contains an explicit timezone indicator, let the Date
        // constructor handle the conversion (it always stores values as vietnam internally).
        if (/[zZ]|[+-]\d{2}:?\d{2}$/.test(normalized)) {
            return new Date(normalized);
        }

        // For naive ISO strings (no timezone info), treat them as vietnam explicitly.
        if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(normalized)) {
            return new Date(`${normalized}Z`);
        }

        return new Date(normalized);
        
    } catch (e) {
        console.error('Error parsing timestamp:', timestamp, e);
        return new Date(timestamp);
    }
}

/**
 * Format timestamp for display
 */
function formatTimestamp(isoString) {
    if (!isoString) return 'Never';
    
    try {
        const date = parseTimestampCorrectly(isoString);
        return date.toLocaleString();
    } catch (e) {
        console.error('Error parsing timestamp:', isoString, e);
        return 'Invalid Date';
    }
}

/**
 * Get status display info
 */
function getStatusInfo(status) {
    switch (status) {
        case 'active':
            return { class: 'active', text: 'Active', icon: 'check-circle' };
        case 'inactive':
            return { class: 'inactive', text: 'Inactive', icon: 'exclamation-triangle' };
        case 'offline':
            return { class: 'offline', text: 'Offline', icon: 'times-circle' };
        default:
            return { class: 'offline', text: 'Unknown', icon: 'question-circle' };
    }
}

/**
 * Load agents from API
 */
async function loadAgents() {
    try {
        console.log(' Loading agents...');
        
        const [agentsResponse, statsResponse] = await Promise.all([
            fetch('/api/agents').catch(err => ({ ok: false, statusText: err.message })),
            fetch('/api/agents/statistics').catch(err => ({ ok: false, statusText: err.message }))
        ]);
        
        if (agentsResponse.ok) {
            const data = await agentsResponse.json();
            agentsData = data.agents || [];
            console.log(' Loaded agents:', agentsData);
            renderAgents(agentsData);
        } else {
            console.error(' Failed to load agents:', agentsResponse.statusText);
            showError('Failed to load agents');
        }
        
        if (statsResponse.ok) {
            const statsData = await statsResponse.json();
            updateStatistics(statsData.data);
        } else {
            updateStatistics();
        }
        
    } catch (error) {
        console.error(' Error loading agents:', error);
        showError('Error loading agents');
        updateStatistics();
    }
}

/**
 * Update statistics display
 */
function updateStatistics(stats = null) {
    if (stats) {
        document.getElementById('totalAgentsCount').textContent = stats.total || 0;
        document.getElementById('activeAgentsCount').textContent = stats.active || 0;
        document.getElementById('inactiveAgentsCount').textContent = stats.inactive || 0;
        document.getElementById('offlineAgentsCount').textContent = stats.offline || 0;
    } else {
        // Calculate from current data
        const total = agentsData.length;
        const active = agentsData.filter(a => a.status === 'active').length;
        const inactive = agentsData.filter(a => a.status === 'inactive').length;
        const offline = agentsData.filter(a => a.status === 'offline').length;
        
        document.getElementById('totalAgentsCount').textContent = total;
        document.getElementById('activeAgentsCount').textContent = active;
        document.getElementById('inactiveAgentsCount').textContent = inactive;
        document.getElementById('offlineAgentsCount').textContent = offline;
    }
}

/**
 * Render agents list
 */
function renderAgents(agents) {
    const container = document.getElementById('agentsContainer');
    
    if (agents.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-laptop-code"></i>
                <h5 class="fw-bold">No Agents Registered</h5>
                <p>No agents have been registered yet. Install and run an agent on your target machines to get started.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '';
    
    agents.forEach((agent, index) => {
        const statusInfo = getStatusInfo(agent.status);
        const lastSeen = formatTimestamp(agent.last_heartbeat);
        const registered = formatTimestamp(agent.registered_date);
        
        // Calculate time since last heartbeat
        let timeSince = '';
        if (agent.last_heartbeat) {
            const now = new Date();
            const lastHeartbeat = parseTimestampCorrectly(agent.last_heartbeat);
            const minutesSince = Math.round((now - lastHeartbeat) / (1000 * 60) * 10) / 10;
            timeSince = ` (${minutesSince}m ago)`;
        }
        
        const agentElement = document.createElement('div');
        agentElement.className = 'p-4 border-bottom agent-item';
        agentElement.dataset.name = (agent.hostname || '').toLowerCase();
        agentElement.dataset.ip = agent.ip_address || '';
        agentElement.dataset.status = agent.status || 'offline';
        
        agentElement.innerHTML = `
            <div class="row align-items-center">
                <div class="col-md-8">
                    <div class="d-flex align-items-center">
                        <div class="me-3">
                            <i class="fas fa-desktop fa-2x text-primary"></i>
                        </div>
                        <div>
                            <h6 class="mb-2 fw-bold">
                                <i class="fas fa-server me-2"></i>
                                ${agent.hostname || 'Unknown Host'}
                            </h6>
                            <div class="d-flex align-items-center mb-2">
                                <span class="agent-status ${statusInfo.class}">
                                    <span class="pulse-indicator ${statusInfo.class}"></span>
                                    ${statusInfo.text}${timeSince}
                                </span>
                                <small class="ms-3 text-muted">
                                    <i class="fas fa-network-wired me-1"></i>
                                    ${agent.ip_address || 'Unknown IP'}
                                </small>
                            </div>
                            <div class="row text-muted">
                                <div class="col-md-6">
                                    <small>
                                        <i class="fas fa-clock me-1"></i>
                                        Last seen: ${lastSeen}
                                    </small>
                                </div>
                                <div class="col-md-6">
                                    <small>
                                        <i class="fas fa-calendar me-1"></i>
                                        Registered: ${registered}
                                    </small>
                                </div>
                            </div>
                            ${agent.agent_version ? `
                                <div class="mt-1">
                                    <small class="text-muted">
                                        <i class="fas fa-code-branch me-1"></i>
                                        Version: ${agent.agent_version}
                                    </small>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 text-md-end">
                    <div class="btn-group btn-group-sm" role="group">
                        <button type="button" class="btn btn-outline-info btn-action" 
                                onclick="pingAgent('${agent.agent_id}')" 
                                title="Ping Agent">
                            <i class="fas fa-wifi"></i>
                        </button>
                        <button type="button" class="btn btn-outline-primary btn-action" 
                                onclick="viewAgentLogs('${agent.agent_id}')" 
                                title="View Logs">
                            <i class="fas fa-file-alt"></i>
                        </button>
                        <button type="button" class="btn btn-outline-danger btn-action" 
                                onclick="removeAgent('${agent.agent_id}')" 
                                title="Remove Agent">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        container.appendChild(agentElement);
    });
}

/**
 * Filter agents based on search and status
 */
function filterAgents() {
    const searchTerm = document.getElementById('agent-search').value.toLowerCase();
    const statusFilter = document.getElementById('status-filter').value;
    const agentItems = document.querySelectorAll('.agent-item');
    
    agentItems.forEach(item => {
        const name = item.dataset.name;
        const ip = item.dataset.ip;
        const status = item.dataset.status;
        
        const matchesSearch = name.includes(searchTerm) || ip.includes(searchTerm);
        const matchesStatus = !statusFilter || status === statusFilter;
        
        if (matchesSearch && matchesStatus) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

/**
 * Action functions
 */
function refreshAgents() {
    const button = event.target;
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Refreshing...';
    button.disabled = true;
    
    loadAgents().finally(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    });
}

function viewAgentLogs(agentId) {
    window.location.href = `/logs?agent_id=${agentId}`;
}

async function pingAgent(agentId) {
    const agent = agentsData.find(a => a.agent_id === agentId);
    const agentName = agent ? `${agent.hostname} (${agent.ip_address})` : agentId;
    
    const pingButton = document.querySelector(`[onclick="pingAgent('${agentId}')"]`);
    if (pingButton) {
        pingButton.disabled = true;
        pingButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    }
    
    try {
        showNotification('info', `Pinging agent ${agentName}...`);
        
        const response = await fetch(`/api/agents/${agentId}/ping`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            const responseTime = data.data.response_time;
            showNotification('success', ` Ping successful! Response time: ${responseTime}s`);
            
            // Update agent status
            if (agent) {
                agent.status = 'active';
                renderAgents(agentsData);
                updateStatistics();
            }
        } else {
            showNotification('danger', ` Ping failed: ${data.error}`);
        }
        
    } catch (error) {
        console.error('Error pinging agent:', error);
        showNotification('danger', `Failed to ping agent: ${error.message}`);
    } finally {
        if (pingButton) {
            pingButton.disabled = false;
            pingButton.innerHTML = '<i class="fas fa-wifi"></i>';
        }
    }
}

async function removeAgent(agentId) {
    const agent = agentsData.find(a => a.agent_id === agentId);
    const agentName = agent ? `${agent.hostname} (${agent.ip_address})` : agentId;
    
    if (!confirm(`Are you sure you want to remove agent "${agentName}"?\n\nThis action cannot be undone.`)) {
        return;
    }
    
    const deleteButton = document.querySelector(`[onclick="removeAgent('${agentId}')"]`);
    if (deleteButton) {
        deleteButton.disabled = true;
        deleteButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    }
    
    try {
        showNotification('info', `Removing agent ${agentName}...`);
        
        const response = await fetch(`/api/agents/${agentId}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('success', `Agent ${agentName} removed successfully`);
            
            // Remove from local data
            const agentIndex = agentsData.findIndex(a => a.agent_id === agentId);
            if (agentIndex >= 0) {
                agentsData.splice(agentIndex, 1);
            }
            
            updateStatistics();
            renderAgents(agentsData);
        } else {
            throw new Error(data.message || 'Failed to remove agent');
        }
        
    } catch (error) {
        console.error('Error removing agent:', error);
        showNotification('danger', `Failed to remove agent: ${error.message}`);
        
        if (deleteButton) {
            deleteButton.disabled = false;
            deleteButton.innerHTML = '<i class="fas fa-trash"></i>';
        }
    }
}

/**
 * Show error message
 */
function showError(message) {
    const container = document.getElementById('agentsContainer');
    container.innerHTML = `
        <div class="text-center py-5">
            <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
            <h5 class="text-danger">Error Loading Agents</h5>
            <p class="text-muted">${message}</p>
            <button class="btn btn-primary" onclick="refreshAgents()">
                <i class="fas fa-redo me-2"></i>Try Again
            </button>
        </div>
    `;
}

/**
 * Event listeners
 */
document.getElementById('agent-search').addEventListener('input', filterAgents);
document.getElementById('status-filter').addEventListener('change', filterAgents);

/**
 * Socket.IO for real-time updates
 */
try {
    if (typeof io !== 'undefined') {
        const socket = io();
        
        socket.on('connect', function() {
            console.log('🔌 Connected to server for real-time updates');
        });
        
        socket.on('agent_heartbeat', function(data) {
            console.log('💓 Agent heartbeat received:', data);
            
            const agentIndex = agentsData.findIndex(a => a.agent_id === data.agent_id);
            if (agentIndex >= 0) {
                const agent = agentsData[agentIndex];
                agent.status = 'active';
                agent.last_heartbeat = data.last_heartbeat || data.timestamp;
                agent.metrics = data.metrics;
                
                renderAgents(agentsData);
                updateStatistics();
            } else {
                // New agent, reload list
                loadAgents();
            }
        });
        
        socket.on('agent_deleted', function(data) {
            console.log(' Agent deleted:', data);
            
            const agentIndex = agentsData.findIndex(a => a.agent_id === data.agent_id);
            if (agentIndex >= 0) {
                agentsData.splice(agentIndex, 1);
                updateStatistics();
                renderAgents(agentsData);
                showNotification('info', `Agent ${data.hostname || data.agent_id} was removed`);
            }
        });
        
    } else {
        console.log(' Socket.IO not available - real-time updates disabled');
    }
} catch (error) {
    console.error(' Socket.IO initialization error:', error);
}

/**
 * Initialize
 */
document.addEventListener('DOMContentLoaded', function() {
    loadAgents();
    
    // Auto-refresh every 30 seconds
    setInterval(loadAgents, 30000);
    
    console.log(' Agent management initialized');
});