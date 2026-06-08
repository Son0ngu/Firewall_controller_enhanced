//  SINGLE VARIABLE DECLARATION BLOCK
let logsData = [];
let selectedLogs = new Set();
let allTimeStats = {};
let currentFilter = {
    time: 'all',
    level: '',
    agent: '',
    search: '',
    limit: 100
};
let currentClearAction = null;
let agentsData = [];

function normalizeAgentField(value) {
    if (value === null || value === undefined) return '';
    const str = typeof value === 'string' ? value : value.toString?.() || '';
    return str.trim();
}

function extractAgentFromObject(obj) {
    if (!obj || typeof obj !== 'object') return '';
    const candidates = [
        obj.display_name,
        obj.host_name,
        obj.hostname,
        obj.machine_name,
        obj.device_name,
        obj.agent_name,
        obj.name,
        obj.label
    ];
    for (const candidate of candidates) {
        const normalized = normalizeAgentField(candidate);
        if (normalized) return normalized;
    }
    return '';
}

function getAgentDisplayName(log) {
    return log.current_agent_host || log.agent_host || log.hostname || log.host_name || log.agent_id || 'Unknown Agent';
}

function getLoggedAgentDisplayName(log) {
    return log.logged_agent_host || log.hostname || log.host_name || '';
}

// Delegate to the shared helper so XSS-escape behavior is identical across
// admin pages (see server/views/static/js/core/utils.js).
const escapeHtml = (value) => window.SaintUtils.escapeHtml(value);

// Server reconstructs a human description from the structured fields the agent
// already sends (see agent/core/handlers.py::handle_domain_detection). This
// runs whenever the agent left `message` as the default placeholder "Log
// entry" - meaning the agent did not attach a custom message but the record
// still carries action, domain, IPs, protocol/port, firewall_mode and the
// domain_allowed / ip_allowed booleans.
function buildLogDescription(log) {
    if (!log || typeof log !== 'object') return '';

    const hasValue = (v) => v !== null && v !== undefined && v !== '' && v !== 'unknown';
    const action = (log.action || '').toString().toUpperCase();
    const domain = hasValue(log.domain) ? log.domain : null;
    const destIp = hasValue(log.dest_ip) ? log.dest_ip : null;
    const srcIp = hasValue(log.source_ip) ? log.source_ip : null;
    const proto = hasValue(log.protocol) ? log.protocol.toString().toUpperCase() : null;
    const port = hasValue(log.port) ? log.port.toString() : null;
    const mode = hasValue(log.firewall_mode) ? log.firewall_mode : null;

    const verbs = {
        BLOCKED: 'Blocked',
        ALLOWED: 'Allowed',
        ALLOWED_BY_IP: 'Allowed by IP (domain not whitelisted)',
        OBSERVED: 'Observed (passive mode)'
    };
    const verb = verbs[action] || (action ? action.toLowerCase() : 'Recorded');

    let target;
    if (proto === 'DNS') {
        target = `DNS query for ${domain || destIp || 'unknown destination'}`;
    } else if (proto) {
        target = `${proto} connection to ${domain || destIp || 'unknown destination'}`;
    } else {
        target = `connection to ${domain || destIp || 'unknown destination'}`;
    }

    const connBits = [];
    if (destIp && destIp !== domain) {
        connBits.push(port ? `${destIp}:${port}` : destIp);
    } else if (port) {
        connBits.push(`port ${port}`);
    }

    const parts = [`${verb} ${target}`];
    if (connBits.length) parts.push(`(${connBits.join(', ')})`);
    if (srcIp) parts.push(`from ${srcIp}`);

    const reasons = [];
    if (action === 'BLOCKED') {
        if (log.domain_allowed === false && log.ip_allowed === false) {
            reasons.push('neither domain nor IP is in the whitelist');
        } else if (log.domain_allowed === false) {
            reasons.push('domain not in whitelist');
        }
    } else if (action === 'ALLOWED_BY_IP') {
        reasons.push('IP whitelisted but SNI/Host is not - possible CDN co-tenant');
    } else if (action === 'ALLOWED') {
        if (log.domain_allowed) reasons.push('domain in whitelist');
        else if (log.ip_allowed) reasons.push('IP in whitelist');
    }
    if (mode) reasons.push(`mode: ${mode}`);

    let desc = parts.join(' ');
    if (reasons.length) desc += ` - ${reasons.join('; ')}`;
    return desc;
}

// Returns the message to show in the Details block: prefers a real custom
// message from the agent, falls back to the reconstructed description when
// message is the default placeholder.
function getLogDetailText(log) {
    const raw = (log && log.message ? String(log.message).trim() : '');
    if (raw && raw !== 'Log entry') return raw;
    return buildLogDescription(log);
}

function normalizeFilterValue(value) {
    return normalizeAgentField(value).toLowerCase();
}

function isKnownAgentName(value) {
    const normalized = normalizeFilterValue(value);
    return normalized && normalized !== 'unknown' && normalized !== 'unknown agent';
}

function getSelectedAgentRecord() {
    if (!currentFilter.agent) return null;
    const selected = currentFilter.agent.toString();
    return agentsData.find(agent => {
        const ids = [agent.agent_id, agent._id, agent.id].map(v => normalizeAgentField(v));
        return ids.includes(selected);
    }) || null;
}

function getSelectedAgentNames() {
    const agent = getSelectedAgentRecord();
    if (!agent) return [];
    const names = [
        agent.hostname,
        agent.display_name,
        agent.current_agent_host,
        agent.agent_host,
        agent.host_name,
        agent.agent_name,
        agent.name,
        agent.label
    ].map(normalizeFilterValue).filter(Boolean);
    return [...new Set(names.filter(isKnownAgentName))];
}

function getLogAgentNames(log) {
    const names = [
        log.current_agent_host,
        log.agent_host,
        log.hostname,
        log.host_name,
        log.logged_agent_host,
        log.agent_name,
        log.machine_name,
        log.device_name
    ].map(normalizeFilterValue).filter(Boolean);
    return [...new Set(names.filter(isKnownAgentName))];
}

function getLogAgentIds(log) {
    return [log.agent_id, log.agent, log.agent_uuid]
        .map(normalizeAgentField)
        .filter(Boolean);
}

function logMatchesSelectedAgent(log) {
    if (!currentFilter.agent) return true;

    const selectedId = currentFilter.agent.toString();
    const selectedNames = getSelectedAgentNames();
    const logNames = getLogAgentNames(log);

    // Demo clones can accidentally share an agent_id. If both sides expose a
    // hostname/display name, treat the visible selected name as authoritative.
    if (selectedNames.length > 0 && logNames.length > 0) {
        return logNames.some(name => selectedNames.includes(name));
    }

    const idMatches = getLogAgentIds(log).some(id => id === selectedId);
    if (idMatches) return true;

    // Fallback for legacy rows where the filter value was a hostname instead
    // of an agent_id.
    const selected = normalizeFilterValue(selectedId);
    return selected && logNames.some(name => name === selected);
}

function logMatchesTimeFilter(log) {
    const timeFilter = currentFilter.time;
    if (!timeFilter || timeFilter === 'all') return true;

    const timestamp = log.timestamp || log.server_received_at;
    const parsed = timestamp ? new Date(timestamp) : null;
    if (!parsed || Number.isNaN(parsed.getTime())) return true;

    const now = new Date();
    const ranges = {
        '1h': 60 * 60 * 1000,
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000,
    };
    const windowMs = ranges[timeFilter];
    return !windowMs || parsed.getTime() >= now.getTime() - windowMs;
}

function getLogSearchText(log) {
    return [
        log.source_ip,
        log.src_ip,
        log.client_ip,
        log.dest_ip,
        log.destination_ip,
        log.destination,
        log.domain,
        log.url,
        log.protocol,
        log.port,
        getAgentDisplayName(log),
        getLoggedAgentDisplayName(log),
        getLogDetailText(log),
        log.action,
        log.level,
    ].map(value => normalizeFilterValue(value)).join(' ');
}

function logMatchesCurrentFilters(log) {
    if (!log) return false;

    const levelFilter = normalizeFilterValue(currentFilter.level);
    if (levelFilter) {
        const level = normalizeFilterValue(log.level || log.action || 'INFO');
        if (level !== levelFilter) return false;
    }

    if (!logMatchesSelectedAgent(log)) return false;

    const searchTerm = normalizeFilterValue(currentFilter.search);
    if (searchTerm && !getLogSearchText(log).includes(searchTerm)) {
        return false;
    }

    return logMatchesTimeFilter(log);
}

function getVisibleLogs(logs = logsData) {
    if (!Array.isArray(logs)) return [];
    return logs.filter(logMatchesCurrentFilters).slice(0, currentFilter.limit);
}

function updateDisplayedLogCount(logs = getVisibleLogs()) {
    const visibleCount = Array.isArray(logs) ? logs.length : 0;
    const logCountEl = document.getElementById('logCount');
    if (logCountEl) {
        logCountEl.textContent = `${visibleCount.toLocaleString()} displayed`;
    }
}

/**
 *  Load FULL statistics với better error handling
 */
async function loadFullStatistics() {
    try {
        SaintLog.debug(' Loading full statistics...');

        const params = new URLSearchParams();
        if (currentFilter.level) params.append('level', currentFilter.level);
        if (currentFilter.agent) params.append('agent_id', currentFilter.agent);
        if (currentFilter.search) params.append('search', currentFilter.search);
        if (currentFilter.time !== 'all') params.append('time_range', currentFilter.time);

        const url = `/api/logs/stats?${params.toString()}`;
        SaintLog.debug(' Fetching statistics from:', url);

        allTimeStats = await SaintAPI.get(url);
        SaintLog.debug(' Statistics loaded:', allTimeStats);
        return allTimeStats;
    } catch (error) {
        // SaintAPIError carries status + body so we don't need a manual
        // .text() pass for diagnostic output.
        console.error(' Error loading statistics:', error);
    }

    // Fallback statistics
    return {
        success: false,
        total: 0,
        allowed: 0,
        blocked: 0,
        warnings: 0
    };
}

/**
 *  Update statistics display với fallback handling
 */
async function updateStatistics() {
    try {
        SaintLog.debug(' Updating statistics display...');
        
        await loadFullStatistics();
        
        SaintLog.debug(' Statistics data:', allTimeStats);
        
        if (allTimeStats && allTimeStats.success) {
            const hasClientFilters = currentFilter.time !== 'all' ||
                              currentFilter.level ||
                              currentFilter.agent ||
                              currentFilter.search;
            const hasFilters = hasClientFilters || allTimeStats.has_filters;

            SaintLog.debug(' Has filters:', hasFilters, '(client:', hasClientFilters, 'server:', allTimeStats.has_filters, ')');
            
            // Update display elements
            const totalEl = document.getElementById('totalLogsCount');
            const allowedEl = document.getElementById('allowedLogsCount');
            const blockedEl = document.getElementById('blockedLogsCount');
            const warningsEl = document.getElementById('warningLogsCount');
            
            // Helper: render stat value
            // - Server RBAC filter only (no client filter): show filtered number only
            // - Client filter active: show "filtered of total"
            // - No filter: show total
            function renderStat(el, filteredVal, totalVal) {
                if (!el) return;
                if (hasClientFilters && hasFilters) {
                    el.innerHTML = `${(filteredVal || 0).toLocaleString()}<small class="text-muted d-block" style="font-size:0.7rem;">of ${(totalVal || 0).toLocaleString()}</small>`;
                } else if (hasFilters) {
                    // Server-side RBAC filter only - don't leak global totals
                    el.textContent = (filteredVal || 0).toLocaleString();
                } else {
                    el.textContent = (totalVal || 0).toLocaleString();
                }
            }

            renderStat(totalEl, allTimeStats.filtered_total, allTimeStats.total);
            renderStat(allowedEl, allTimeStats.filtered_allowed, allTimeStats.allowed);
            renderStat(blockedEl, allTimeStats.filtered_blocked, allTimeStats.blocked);
            renderStat(warningsEl, allTimeStats.filtered_warnings, allTimeStats.warnings);
            
            // Update log count
            updateDisplayedLogCount();
            
        } else {
            SaintLog.debug(' Using fallback statistics calculation');
            // Fallback: calculate from current logs data
            const visibleLogs = getVisibleLogs();
            const total = visibleLogs.length;
            const allowed = visibleLogs.filter(log => (log.level === 'ALLOWED' || log.action === 'ALLOWED')).length;
            const blocked = visibleLogs.filter(log => (log.level === 'BLOCKED' || log.action === 'BLOCKED')).length;
            const warnings = visibleLogs.filter(log => log.level === 'WARNING').length;
            
            document.getElementById('totalLogsCount').innerHTML = `${total.toLocaleString()}<small class="text-muted d-block">limited view</small>`;
            document.getElementById('allowedLogsCount').innerHTML = `${allowed.toLocaleString()}<small class="text-muted d-block">limited view</small>`;
            document.getElementById('blockedLogsCount').innerHTML = `${blocked.toLocaleString()}<small class="text-muted d-block">limited view</small>`;
            document.getElementById('warningLogsCount').innerHTML = `${warnings.toLocaleString()}<small class="text-muted d-block">limited view</small>`;
            document.getElementById('logCount').textContent = `${total.toLocaleString()} displayed`;
        }
        
    } catch (error) {
        console.error(' Error updating statistics:', error);
        // Emergency fallback
        document.getElementById('totalLogsCount').textContent = logsData.length.toLocaleString();
        document.getElementById('allowedLogsCount').textContent = '0';
        document.getElementById('blockedLogsCount').textContent = '0';
        document.getElementById('warningLogsCount').textContent = '0';
        updateDisplayedLogCount();
    }
}

/**
 *  Load logs function
 */
async function loadLogs() {
    try {
        SaintLog.debug('Loading logs with filter:', currentFilter);
        
        const params = new URLSearchParams();
        
        // Add all filter parameters
        if (currentFilter.level) {
            params.append('level', currentFilter.level);
            SaintLog.debug('  Level filter:', currentFilter.level);
        }
        
        if (currentFilter.agent) {
            params.append('agent_id', currentFilter.agent);
            SaintLog.debug('  Agent filter:', currentFilter.agent);
        }
        
        if (currentFilter.search) {
            params.append('search', currentFilter.search);
            SaintLog.debug('  Search filter:', currentFilter.search);
        }
        
        if (currentFilter.time && currentFilter.time !== 'all') {
            params.append('time_range', currentFilter.time);
            SaintLog.debug('  Time filter:', currentFilter.time);
        }
        
        params.append('limit', currentFilter.limit);
        SaintLog.debug('  Limit:', currentFilter.limit);
        
        const url = `/api/logs?${params.toString()}`;
        SaintLog.debug('Fetching from URL:', url);

        let data;
        try {
            data = await SaintAPI.get(url);
        } catch (apiErr) {
            // SaintAPIError carries status + parsed body so we can surface
            // the same diagnostic info the old hand-rolled fetch did.
            console.error('Failed to load logs:', apiErr.status, apiErr.body);
            showError(`Failed to load logs: ${apiErr.status || apiErr.message}`);
            return;
        }

        SaintLog.debug('Response structure:', {
            success: data.success,
            hasLogs: !!data.logs,
            logsLength: data.logs ? data.logs.length : 0,
            total: data.total
        });

        if (data.logs && Array.isArray(data.logs)) {
            logsData = data.logs;
            SaintLog.debug('Logs data assigned:', logsData.length, 'items');
            if (logsData.length > 0) {
                SaintLog.debug('First log sample:', JSON.stringify(logsData[0], null, 2));
            }
            renderLogs(getVisibleLogs(logsData));
            await updateStatistics();
        } else {
            console.error('No valid logs array in response');
            SaintLog.debug('Full response:', data);
            showError('Invalid response format - no logs array');
        }

    } catch (error) {
        console.error('Error loading logs:', error);
        showError('Error loading logs: ' + error.message);
        await updateStatistics();
    }
}

function filterLogsBySelectedAgent(logs) {
    if (!currentFilter.agent || !Array.isArray(logs)) {
        return logs;
    }

    const expected = currentFilter.agent.toString();
    const filtered = logs.filter(logMatchesSelectedAgent);
    const hidden = logs.length - filtered.length;
    if (hidden > 0) {
        console.warn(`Hidden ${hidden} log(s) outside selected agent filter ${expected}`);
    }
    return filtered;
}

/**
 * Load agents for filter dropdown
 */
async function loadAgentsForFilter() {
    try {
        SaintLog.debug('Loading agents for filter...');
        const data = await SaintAPI.get('/api/agents');
        agentsData = data.agents || [];
        SaintLog.debug(' Loaded agents:', agentsData.length);
        populateAgentFilter();
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

/**
 * Populate agent filter dropdown
 */
function populateAgentFilter() {
    const agentFilter = document.getElementById('agent-filter');
    if (!agentFilter) return;
    
    const currentValue = agentFilter.value;
    
    // Clear and add default option
    agentFilter.innerHTML = '<option value="">All Agents</option>';
    
    // Sort agents by hostname
    const sortedAgents = [...agentsData].sort((a, b) => {
        const nameA = (a.hostname || a.display_name || a.agent_id || '').toLowerCase();
        const nameB = (b.hostname || b.display_name || b.agent_id || '').toLowerCase();
        return nameA.localeCompare(nameB);
    });
    
    // Add agent options
    sortedAgents.forEach(agent => {
        const option = document.createElement('option');
        const agentId = agent.agent_id || agent._id || '';
        const displayName = agent.hostname || agent.display_name || agentId;
        const status = agent.status || 'unknown';
        
        option.value = agentId;
        option.textContent = `${displayName} (${status})`;
        
        // Add icon based on status
        if (status === 'active') {
            option.textContent = `${displayName}`;
        } else if (status === 'offline') {
            option.textContent = ` ${displayName}`;
        } else if (status === 'pending') {
            option.textContent = `⏳ ${displayName}`;
        }
        
        agentFilter.appendChild(option);
    });
    
    // Restore previous selection
    if (currentValue) {
        agentFilter.value = currentValue;
    }

    if (window.initCustomSelect) {
        window.initCustomSelect('agent-filter');
    }
    
    SaintLog.debug(`Populated agent filter with ${sortedAgents.length} agents`);
}

/**
 *  Filter change handler
 */
function onFilterChange() {
    SaintLog.debug('Filter changed, current state:', currentFilter);
    
    const levelFilter = document.getElementById('level-filter');
    const agentFilter = document.getElementById('agent-filter');
    const searchInput = document.getElementById('log-search');
    
    currentFilter.level = levelFilter ? levelFilter.value : '';
    currentFilter.agent = agentFilter ? agentFilter.value : '';
    currentFilter.search = searchInput ? searchInput.value : '';
    
    SaintLog.debug('Reloading logs with filter:', currentFilter);
    loadLogs();
}

/**
 *  Render logs
 */
function renderLogs(logs) {
    SaintLog.debug('🎨 renderLogs called with:', logs ? logs.length : 0, 'logs');
    
    logs = Array.isArray(logs) ? logs : [];
    updateDisplayedLogCount(logs);

    const container = document.getElementById('logsContainer');
    
    if (!container) {
        console.error(' Logs container not found');
        return;
    }
    
    if (logs.length === 0) {
        SaintLog.debug(' No logs to render');
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-file-alt"></i>
                <h5>No logs found</h5>
                <p class="text-muted">No log entries match your current filters.</p>
                <button class="btn btn-outline-primary btn-sm" onclick="clearFilters()">
                    <i class="fas fa-filter"></i> Clear Filters
                </button>
            </div>
        `;
        return;
    }
    
    SaintLog.debug(' Starting to render', logs.length, 'logs');
    container.innerHTML = '';
    
    let renderedCount = 0;
    
    logs.forEach((log, index) => {
        try {
            //  Enhanced data extraction with better fallbacks
            SaintLog.debug(` Processing log ${index}:`, log);
            
            const timestamp = log.timestamp ? 
                (typeof log.timestamp === 'string' ? 
                    new Date(log.timestamp).toLocaleString('vi-VN') : 
                    log.timestamp.toLocaleString ? log.timestamp.toLocaleString('vi-VN') : log.timestamp
                ) : 
                'Unknown';
                
            const level = (log.level || log.action || 'INFO').toString().toUpperCase();
            const action = (log.action || 'UNKNOWN').toString().toUpperCase();
            
            //  FIX: Better data extraction with multiple fallbacks
            const domain = log.domain || log.destination || log.url || 'N/A';
            const source_ip = log.source_ip || log.src_ip || log.client_ip || 'N/A';
            const dest_ip = log.dest_ip || log.ip || log.destination_ip || 'N/A';
            const agentId = (log.agent_id || log.agent || '').toString();
            const agentHost = getAgentDisplayName(log);
            const loggedAgentHost = getLoggedAgentDisplayName(log);
            const hostChangeTitle = log.agent_host_changed && loggedAgentHost
                ? ` title="Logged as ${escapeHtml(loggedAgentHost)}"`
                : '';
            const protocol = log.protocol || 'N/A';
            const port = log.port ? log.port.toString() : 'N/A';
            const detailText = getLogDetailText(log);
            const logId = log._id || log.id || index.toString();
            
            const logElement = document.createElement('div');
            logElement.className = 'p-3 border-bottom log-item';
            logElement.dataset.level = level.toLowerCase();
            logElement.dataset.agent = `${agentId} ${agentHost}`.toLowerCase();
            logElement.dataset.search = `${source_ip} ${dest_ip} ${domain} ${detailText}`.toLowerCase();
            
            logElement.innerHTML = `
                <div class="row align-items-center">
                    <div class="col-auto">
                        <input type="checkbox" class="form-check-input log-checkbox" value="${logId}">
                    </div>
                    <div class="col">
                        <div class="d-flex align-items-start justify-content-between">
                            <div class="flex-grow-1">
                                <div class="d-flex align-items-center mb-2">
                                    <span class="log-level ${level}">${level}</span>
                                    <span class="log-timestamp ms-2">${timestamp}</span>
                                    <span class="log-agent ms-2"${hostChangeTitle}>${agentHost}</span>
                                </div>
                                
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-1">
                                            <small class="text-muted">Domain:</small>
                                            <strong class="ms-1">${domain}</strong>
                                        </div>
                                        <div class="mb-1">
                                            <small class="text-muted">Source:</small>
                                            <span class="log-ip ms-1">${source_ip}</span>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-1">
                                            <small class="text-muted">Destination:</small>
                                            <span class="log-ip ms-1">${dest_ip}</span>
                                        </div>
                                        <div class="mb-1">
                                            <small class="text-muted">Protocol:</small>
                                            <span class="log-action ms-1">${protocol}:${port}</span>
                                        </div>
                                    </div>
                                </div>
                                
                                ${detailText ? `
                                    <div class="log-details mt-2">
                                        <small class="text-muted">Details:</small>
                                        <div class="mt-1">${escapeHtml(detailText)}</div>
                                    </div>
                                ` : ''}
                            </div>
                            
                            <div class="ms-3">
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
                                            type="button" data-bs-toggle="dropdown">
                                        <i class="fas fa-ellipsis-v"></i>
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <a class="dropdown-item" href="javascript:void(0)" 
                                               onclick="showLogDetails('${logId}')">
                                                <i class="fas fa-eye me-2"></i>View Details
                                            </a>
                                        </li>
                                        <li>
                                            <a class="dropdown-item" href="javascript:void(0)" 
                                               onclick="exportSingleLog('${logId}')">
                                                <i class="fas fa-download me-2"></i>Export
                                            </a>
                                        </li>
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <a class="dropdown-item text-danger" href="javascript:void(0)" 
                                               onclick="clearSingleLog('${logId}')">
                                                <i class="fas fa-trash me-2"></i>Delete
                                            </a>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            container.appendChild(logElement);
            renderedCount++;
            
        } catch (error) {
            console.error(` Error rendering log ${index}:`, error, log);
        }
    });
    
    // Add event listeners for checkboxes
    container.querySelectorAll('.log-checkbox').forEach(cb => {
        cb.addEventListener('change', updateSelectedLogs);
    });
    
    SaintLog.debug(` Successfully rendered ${renderedCount}/${logs.length} logs`);
}

/**
 *  Clear confirmation
 */
function showClearConfirmation(action, count = 0, message = '') {
    currentClearAction = action;
    
    // Check if modal elements exist
    const modalTitle = document.getElementById('clearModalTitle');
    const modalMessage = document.getElementById('clearModalMessage');
    const checkbox = document.getElementById('confirmClearCheckbox');
    const confirmBtn = document.getElementById('modalConfirmClearBtn');
    
    if (!modalTitle || !modalMessage || !checkbox || !confirmBtn) {
        console.error(' Modal elements not found');
        return;
    }
    
    let title, modalMessageText;
    
    switch (action) {
        case 'all':
            title = 'Clear All Logs?';
            modalMessageText = `This will permanently delete all system logs and cannot be undone.`;
            break;
        case 'selected':
            title = `Clear ${count} Selected Logs?`;
            modalMessageText = `This will permanently delete the ${count} selected logs and cannot be undone.`;
            break;
        case 'old':
            title = 'Clear Old Logs?';
            modalMessageText = 'This will permanently delete all logs older than 30 days and cannot be undone.';
            break;
        case 'single':
            title = 'Clear This Log?';
            modalMessageText = 'This will permanently delete this log entry and cannot be undone.';
            break;
        default:
            title = 'Clear Logs?';
            modalMessageText = message || 'This action cannot be undone.';
    }
    
    modalTitle.textContent = title;
    modalMessage.textContent = modalMessageText;
    
    // Reset checkbox and button
    checkbox.checked = false;
    confirmBtn.disabled = true;
    
    const modal = new bootstrap.Modal(document.getElementById('clearConfirmModal'));
    modal.show();
}

/**
 *  Perform clear action - FIXED
 */
async function performClearAction() {
    if (!currentClearAction) return;
    
    const confirmBtn = document.getElementById('modalConfirmClearBtn');
    if (!confirmBtn) return;
    
    const originalText = confirmBtn.innerHTML;
    confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Clearing...';
    confirmBtn.disabled = true;
    
    try {
        let requestBody = {};
        let successMessage = '';
        
        switch (currentClearAction) {
            case 'all':
                requestBody = { action: 'all' };
                successMessage = 'All logs cleared successfully';
                break;
                
            case 'selected':
                const selectedLogIds = Array.from(selectedLogs);
                requestBody = { 
                    action: 'selected',
                    log_ids: selectedLogIds 
                };
                successMessage = `${selectedLogIds.length} selected logs cleared successfully`;
                break;
                
            case 'old':
                requestBody = { action: 'old' };
                successMessage = 'Old logs cleared successfully';
                break;
                
            case 'single':
                if (currentClearAction.logId) {
                    requestBody = { 
                        action: 'selected',
                        log_ids: [currentClearAction.logId] 
                    };
                    successMessage = 'Log cleared successfully';
                }
                break;
                
            default:
                requestBody = { action: 'all' };
                successMessage = 'Logs cleared successfully';
        }
        
        SaintLog.debug(' Clearing logs with:', requestBody);

        let result;
        try {
            // SaintAPI sends DELETE with a JSON body via the same _send
            // path. It attaches X-CSRF-Token automatically and parses the
            // JSON response. If the server returns non-2xx the helper
            // throws SaintAPIError carrying status + body.
            result = await SaintAPI.raw('/api/logs/clear', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                body: JSON.stringify(requestBody),
            }).then(async (response) => {
                SaintLog.debug(' Clear response status:', response.status);
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorText}`);
                }
                return response.json();
            });
        } catch (apiErr) {
            console.error(' Clear failed:', apiErr);
            throw apiErr;
        }

        SaintLog.debug(' Clear result:', result);

        if (result.success) {
            const actualDeleted = result.deleted_count || 0;
            if (actualDeleted > 0) {
                showNotification('success', `${actualDeleted} logs cleared successfully`);
                await loadLogs();
                selectedLogs.clear();
                updateSelectedLogs();
            } else {
                showNotification('info', 'No logs were found to clear');
            }
            const modal = bootstrap.Modal.getInstance(document.getElementById('clearConfirmModal'));
            if (modal) modal.hide();
        } else {
            throw new Error(result.error || 'Failed to clear logs');
        }

    } catch (error) {
        console.error(' Error clearing logs:', error);
        showNotification('danger', `Failed to clear logs: ${error.message}`);
    } finally {
        confirmBtn.innerHTML = originalText;
        confirmBtn.disabled = false;
        currentClearAction = null;
    }
}

/**
 *  Single log clear
 */
function clearSingleLog(logId) {
    currentClearAction = { action: 'single', logId: logId };
    showClearConfirmation('single');
}

/**
 *  Filter logs
 */
function filterLogs() {
    renderLogs(getVisibleLogs(logsData));
}

/**
 *  Show log details
 */
function showLogDetails(logId) {
    const log = logsData.find(l => (l._id || l.id || logsData.indexOf(l).toString()) === logId);
    if (!log) return;
    
    const modal = new bootstrap.Modal(document.getElementById('logDetailsModal'));
    const content = document.getElementById('logDetailsContent');
    
    if (!content) return;
    
    content.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h6 class="fw-bold mb-3">Basic Information</h6>
                <table class="table table-sm">
                    <tr><td class="fw-semibold">Timestamp:</td><td>${log.timestamp ? new Date(log.timestamp).toLocaleString() : 'Unknown'}</td></tr>
                    <tr><td class="fw-semibold">Level:</td><td><span class="log-level ${log.level || 'INFO'}">${log.level || log.action || 'INFO'}</span></td></tr>
                    <tr><td class="fw-semibold">Source IP:</td><td><code>${log.source_ip || log.ip || 'Unknown'}</code></td></tr>
                    <tr><td class="fw-semibold">Destination:</td><td>${log.destination || log.domain || log.url || 'N/A'}</td></tr>
                    <tr><td class="fw-semibold">Agent:</td><td><span class="log-agent">${getAgentDisplayName(log)}</span></td></tr>
                    ${log.agent_host_changed && getLoggedAgentDisplayName(log) ? `
                    <tr><td class="fw-semibold">Logged as:</td><td><span class="text-muted">${escapeHtml(getLoggedAgentDisplayName(log))}</span></td></tr>
                    ` : ''}
                </table>
            </div>
            <div class="col-md-6">
                <h6 class="fw-bold mb-3">Additional Details</h6>
                <table class="table table-sm">
                    <tr><td class="fw-semibold">Protocol:</td><td>${log.protocol || 'Unknown'}</td></tr>
                    <tr><td class="fw-semibold">Port:</td><td>${log.port || log.destination_port || 'Unknown'}</td></tr>
                    <tr><td class="fw-semibold">Size:</td><td>${log.size || log.packet_size || 'Unknown'}</td></tr>
                    <tr><td class="fw-semibold">Action:</td><td>${log.action || 'Unknown'}</td></tr>
                    <tr><td class="fw-semibold">Rule ID:</td><td>${log.rule_id || 'N/A'}</td></tr>
                </table>
            </div>
        </div>
        ${(() => {
            const detail = getLogDetailText(log);
            return detail ? `
                <div class="mt-3">
                    <h6 class="fw-bold">Description</h6>
                    <div class="alert alert-light">
                        <code>${escapeHtml(detail)}</code>
                    </div>
                </div>
            ` : '';
        })()}
    `;
    
    modal.show();
}

/**
 *  Export functionality
 */
function exportLogs(logs = logsData) {
    const csvContent = [
        ['Timestamp', 'Level', 'Source IP', 'Destination', 'Agent', 'Message'].join(','),
        ...logs.map(log => [
            log.timestamp || '',
            log.level || log.action || '',
            log.source_ip || log.ip || '',
            log.destination || log.domain || log.url || '',
            getAgentDisplayName(log),
            (log.message || '').replace(/,/g, ';')
        ].join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `firewall-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
    
    showNotification('success', `Exported ${logs.length} logs successfully`);
}

function exportSingleLog(logId) {
    const log = logsData.find(l => (l._id || l.id || logsData.indexOf(l).toString()) === logId);
    if (log) {
        exportLogs([log]);
    }
}

/**
 *  Utility functions
 */
function refreshLogs() {
    const button = document.getElementById('refreshBtn');
    if (button) {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        button.disabled = true;
        
        loadLogs().finally(() => {
            button.innerHTML = originalText;
            button.disabled = false;
        });
    }
}

function clearFilters() {
    currentFilter = { time: 'all', level: '', agent: '', search: '', limit: 100 };
    
    const searchInput = document.getElementById('log-search');
    const levelFilter = document.getElementById('level-filter');
    const agentFilter = document.getElementById('agent-filter');
    
    if (searchInput) searchInput.value = '';
    if (levelFilter) levelFilter.value = '';
    if (agentFilter) agentFilter.value = '';
    
    document.querySelector('.time-pill.active')?.classList.remove('active');
    document.querySelector('[data-time="all"]')?.classList.add('active');
    
    loadLogs();
}

function selectAllLogs() {
    const selectAllCheckbox = document.getElementById('selectAllLogs');
    const logCheckboxes = document.querySelectorAll('.log-checkbox');
    
    if (selectAllCheckbox) {
        logCheckboxes.forEach(cb => {
            cb.checked = selectAllCheckbox.checked;
        });
        updateSelectedLogs();
    }
}

function updateSelectedLogs() {
    const checkboxes = document.querySelectorAll('.log-checkbox:checked');
    selectedLogs.clear();
    
    checkboxes.forEach(cb => selectedLogs.add(cb.value));
    
    const selectedCountEl = document.getElementById('selectedCount');
    if (selectedCountEl) {
        selectedCountEl.textContent = selectedLogs.size;
    }
    
    const bulkActions = document.getElementById('bulkActions');
    if (bulkActions) {
        if (selectedLogs.size > 0) {
            bulkActions.classList.add('show');
        } else {
            bulkActions.classList.remove('show');
        }
    }
    
    // Update select all checkbox state
    const totalCheckboxes = document.querySelectorAll('.log-checkbox').length;
    const selectAllCheckbox = document.getElementById('selectAllLogs');
    
    if (selectAllCheckbox) {
        if (selectedLogs.size === 0) {
            selectAllCheckbox.indeterminate = false;
            selectAllCheckbox.checked = false;
        } else if (selectedLogs.size === totalCheckboxes) {
            selectAllCheckbox.indeterminate = false;
            selectAllCheckbox.checked = true;
        } else {
            selectAllCheckbox.indeterminate = true;
        }
    }
}

function showError(message) {
    const container = document.getElementById('logsContainer');
    if (container) {
        container.innerHTML = `
            <div class="text-center py-5">
                <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
                <h5 class="text-danger">Error Loading Logs</h5>
                <p class="text-muted">${message}</p>
                <button class="btn btn-primary" onclick="refreshLogs()">
                    <i class="fas fa-redo me-2"></i>Try Again
                </button>
            </div>
        `;
    }
}

function showNotification(type, message) {
    // Was a hand-rolled top-right alert. Routed through SaintToast so logs.js
    // matches the rest of the admin UI (same z-index, same close behaviour,
    // same dismiss timing). Type strings map cleanly:
    //   'success' / 'warning' / 'info' / 'danger'(→error)
    if (window.SaintToast) {
        const mappedType = (type === 'danger') ? 'error' : type;
        window.SaintToast.show(message, mappedType);
        return;
    }
    // Fallback only fires if base.html didn't load core/toast.js — keep the
    // legacy alert path so an isolated rendering of this page still works.
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(notification);
    setTimeout(() => { if (notification.parentNode) notification.remove(); }, 5000);
}

/**
 *  SINGLE INITIALIZATION
 */
document.addEventListener('DOMContentLoaded', function() {
    SaintLog.debug('Initializing logs management...');
    
    // Initialize custom selects for static elements
    ['level-filter', 'limit-select'].forEach(id => {
        if (window.initCustomSelect) window.initCustomSelect(id);
    });

    // Time filter pills
    document.querySelectorAll('.time-pill').forEach(pill => {
        pill.addEventListener('click', function() {
            document.querySelector('.time-pill.active')?.classList.remove('active');
            this.classList.add('active');
            currentFilter.time = this.dataset.time;
            SaintLog.debug('Time filter changed to:', currentFilter.time);
            onFilterChange();
        });
    });
    
    // Search input
    const searchInput = document.getElementById('log-search');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            currentFilter.search = this.value;
            SaintLog.debug('Search filter changed to:', currentFilter.search);
            filterLogs(); // Use filterLogs for client-side search
        });
    }
    
    // Level filter
    const levelFilter = document.getElementById('level-filter');
    if (levelFilter) {
        levelFilter.addEventListener('change', function() {
            currentFilter.level = this.value;
            SaintLog.debug('Level filter changed to:', currentFilter.level);
            onFilterChange();
        });
    }
    
    // Agent filter
    const agentFilter = document.getElementById('agent-filter');
    if (agentFilter) {
        agentFilter.addEventListener('change', function() {
            currentFilter.agent = this.value;
            SaintLog.debug('Agent filter changed to:', currentFilter.agent);
            onFilterChange();
        });
    }
    
    // Limit select
    const limitSelect = document.getElementById('limit-select');
    if (limitSelect) {
        limitSelect.addEventListener('change', function() {
            currentFilter.limit = parseInt(this.value);
            SaintLog.debug('Limit changed to:', currentFilter.limit);
            loadLogs();
        });
    }
    
    // Control buttons
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshLogs);
    }
    
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => exportLogs());
    }
    
    // Select all functionality
    const selectAllLogs = document.getElementById('selectAllLogs');
    if (selectAllLogs) {
        selectAllLogs.addEventListener('change', selectAllLogs);
    }
    
    // Clear functionality
    const clearSelectedBtn = document.getElementById('clearSelectedBtn');
    if (clearSelectedBtn) {
        clearSelectedBtn.addEventListener('click', function(e) {
            e.preventDefault();
            if (selectedLogs.size === 0) {
                showNotification('warning', 'No logs selected');
                return;
            }
            showClearConfirmation('selected', selectedLogs.size);
        });
    }
    
    const clearOldLogsBtn = document.getElementById('clearOldLogsBtn');
    if (clearOldLogsBtn) {
        clearOldLogsBtn.addEventListener('click', function(e) {
            e.preventDefault();
            showClearConfirmation('old');
        });
    }
    
    const clearAllLogsBtn = document.getElementById('clearAllLogsBtn');
    if (clearAllLogsBtn) {
        clearAllLogsBtn.addEventListener('click', function(e) {
            e.preventDefault();
            showClearConfirmation('all');
        });
    }
    
    // Bulk actions
    const bulkClearBtn = document.getElementById('bulkClearBtn');
    if (bulkClearBtn) {
        bulkClearBtn.addEventListener('click', function() {
            if (selectedLogs.size === 0) {
                showNotification('warning', 'No logs selected');
                return;
            }
            showClearConfirmation('selected', selectedLogs.size);
        });
    }
    
    const bulkExportBtn = document.getElementById('bulkExportBtn');
    if (bulkExportBtn) {
        bulkExportBtn.addEventListener('click', function() {
            const selectedLogsData = logsData.filter(log => 
                selectedLogs.has(log._id || log.id || logsData.indexOf(log).toString())
            );
            exportLogs(selectedLogsData);
        });
    }
    
    // Modal confirmation
    const confirmClearCheckbox = document.getElementById('confirmClearCheckbox');
    if (confirmClearCheckbox) {
        confirmClearCheckbox.addEventListener('change', function() {
            const confirmBtn = document.getElementById('modalConfirmClearBtn');
            if (confirmBtn) {
                confirmBtn.disabled = !this.checked;
            }
        });
    }
    
    const modalConfirmClearBtn = document.getElementById('modalConfirmClearBtn');
    if (modalConfirmClearBtn) {
        modalConfirmClearBtn.addEventListener('click', performClearAction);
    }
    
    // Load initial data
    SaintLog.debug('Loading initial data...');
    loadAgentsForFilter()
        .then(() => {
            SaintLog.debug('Agent filter loaded successfully');
            loadLogs();
        })
        .catch(error => {
            console.error('Error loading agents:', error);
            loadLogs(); // Load logs anyway
        });
    
    SaintLog.debug('Logs management initialized');
});

// Socket.IO for real-time updates
try {
    if (typeof io !== 'undefined') {
        const socket = io();
        
        socket.on('connect', function() {
            SaintLog.debug('Connected for real-time updates');
        });
        
        socket.on('new_log', function(logData) {
            SaintLog.debug(' New log received:', logData);
            if (!logMatchesCurrentFilters(logData)) {
                SaintLog.debug(' New log skipped by active filters:', currentFilter);
                updateStatistics();
                return;
            }
            logsData.unshift(logData);
            logsData = logsData.slice(0, currentFilter.limit);
            updateStatistics();
            renderLogs(getVisibleLogs(logsData));
        });
        
        socket.on('logs_cleared', function(data) {
            SaintLog.debug(' Logs cleared:', data);
            showNotification('info', `${data.count} logs were cleared`);
            loadLogs();
        });
        
    } else {
        SaintLog.debug(' Socket.IO not available');
    }
} catch (error) {
    console.error(' Socket.IO error:', error);
}

//  Add emergency test function
function emergencyTest() {
    SaintLog.debug('🚨 Running emergency test');

    // Test direct API call
    SaintAPI.get('/api/logs?limit=5')
        .then(data => {
            SaintLog.debug(' Emergency test parsed data:', data);
            if (data.logs) {
                SaintLog.debug(' Emergency test logs count:', data.logs.length);
                renderLogs(data.logs);
            }
        })
        .catch(error => {
            console.error(' Emergency test error:', error);
        });
}

//  Add test render function
function testRender() {
    SaintLog.debug(' Testing render with sample data');
    
    const sampleLogs = [
        {
            _id: 'test1',
            timestamp: new Date().toISOString(),
            level: 'ALLOWED',
            action: 'ALLOWED',
            domain: 'google.com',
            source_ip: '192.168.1.100',
            dest_ip: '8.8.8.8',
            agent_id: 'test-agent',
            protocol: 'TCP',
            port: '443',
            message: 'Test log entry'
        },
        {
            _id: 'test2',
            timestamp: new Date().toISOString(),
            level: 'BLOCKED',
            action: 'BLOCKED',
            domain: 'malicious-site.com',
            source_ip: '192.168.1.100',
            dest_ip: '1.2.3.4',
            agent_id: 'test-agent',
            protocol: 'TCP',
            port: '80',
            message: 'Test blocked entry'
        }
    ];
    
    SaintLog.debug(' Rendering sample logs:', sampleLogs);
    renderLogs(sampleLogs);
}

function renderLogItem(log, index) {
    const logId = log._id || log.id || index.toString();
    
    // 🎨 CHECK: Is this a lifecycle event (startup/shutdown)?
    let eventType = log.event_type || '';
    const message = (log.message || '').toLowerCase();
    
    // Also detect lifecycle events from message if event_type is not set
    if (!eventType) {
        if (message.includes('agent startup') || message.includes('agent started')) {
            eventType = 'agent_startup';
        } else if (message.includes('agent shutdown') || message.includes('agent stopped')) {
            eventType = 'agent_shutdown';
        }
    }
    
    const isLifecycleEvent = ['agent_startup', 'agent_shutdown', 'agent_stopped'].includes(eventType);
    
    if (isLifecycleEvent) {
        // Ensure event_type is set for rendering
        log.event_type = eventType;
        return renderLifecycleEvent(log, logId);
    }
    
    //  FIX: Enhanced protocol display
    let protocolDisplay = log.protocol || 'unknown';
    let portDisplay = log.port || 'unknown';
    
    if (protocolDisplay !== 'unknown' && portDisplay !== 'unknown') {
        protocolDisplay = `${protocolDisplay}:${portDisplay}`;
    } else if (protocolDisplay === 'unknown' && portDisplay !== 'unknown') {
        protocolDisplay = `Port ${portDisplay}`;
    }
    
    //  FIX: Enhanced source IP display
    let sourceDisplay = log.source_ip || 'unknown';
    if (sourceDisplay === 'unknown') {
        sourceDisplay = '<span class="text-muted">Local</span>';
    } else {
        sourceDisplay = `<span class="log-ip">${sourceDisplay}</span>`;
    }
    
    //  FIX: Enhanced destination display
    let destinationDisplay = log.destination || log.domain || log.dest_ip || 'unknown';
    if (log.service_type && log.service_type !== 'unknown') {
        destinationDisplay += `<small class="text-muted ms-1">(${log.service_type})</small>`;
    }
    
    const agentId = (log.agent_id || log.agent || '').toString();
    const agentHost = getAgentDisplayName(log);
    
    return `
        <div class="log-item p-3 border-bottom" data-log-id="${logId}" 
             data-level="${(log.level || 'info').toLowerCase()}"
             data-agent="${`${agentId} ${agentHost}`.toLowerCase()}"
             data-search="${(log.domain || '' + log.destination || '' + log.source_ip || '' + log.message || '').toLowerCase()}">
            
            <div class="row align-items-center">
                <div class="col-auto">
                    <input type="checkbox" class="form-check-input log-checkbox" value="${logId}">
                </div>
                
                <div class="col-auto">
                    <span class="log-level ${log.level || 'INFO'}">${log.level || 'INFO'}</span>
                </div>
                
                <div class="col-2">
                    <div class="log-timestamp">${formatTimestamp(log.timestamp)}</div>
                    <small class="text-muted">${log.display_time || formatTime(log.timestamp)}</small>
                </div>
                
                <div class="col-3">
                    <div class="fw-medium">${destinationDisplay}</div>
                    ${log.dest_ip && log.dest_ip !== 'unknown' ? `
                        <small class="text-muted d-block">
                            <i class="fas fa-arrow-right me-1"></i>${log.dest_ip}
                        </small>
                    ` : ''}
                </div>
                
                <div class="col-2">
                    <div class="small">
                        <div class="mb-1">
                            <i class="fas fa-network-wired me-1"></i>
                            Protocol<span class="log-action ms-1">${protocolDisplay}</span>
                        </div>
                        <div>
                            <i class="fas fa-desktop me-1"></i>
                            Source${sourceDisplay}
                        </div>
                    </div>
                </div>
                
                <div class="col-2">
                    <span class="log-agent">${agentHost}</span>
                    ${log.process_name ? `
                        <small class="d-block text-muted mt-1">
                            <i class="fas fa-cog me-1"></i>${log.process_name}
                        </small>
                    ` : ''}
                </div>
                
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-ellipsis-v"></i>
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="showLogDetails('${logId}')">
                                <i class="fas fa-info-circle me-2"></i>View Details
                            </a></li>
                            <li><a class="dropdown-item" href="#" onclick="exportSingleLog('${logId}')">
                                <i class="fas fa-download me-2"></i>Export
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="#" onclick="clearSingleLog('${logId}')">
                                <i class="fas fa-trash me-2"></i>Delete
                            </a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            ${log.message && log.message !== 'Log entry' ? `
                <div class="log-details mt-2">
                    <i class="fas fa-comment-alt me-2"></i>${log.message}
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * 🎨 RENDER LIFECYCLE EVENTS (Startup/Shutdown/Stopped)
 * Beautiful cards for agent lifecycle events instead of showing "unknown" values
 */
function renderLifecycleEvent(log, logId) {
    const eventType = log.event_type || 'agent_event';
    const agentHost = getAgentDisplayName(log);
    
    // Define event styling based on type
    let eventConfig = {
        'agent_startup': {
            icon: 'fa-rocket',
            gradient: 'linear-gradient(135deg, #C7D2FE 0%, #6366F1 100%)',
            title: 'Agent Started',
            badge: 'bg-info',
            borderColor: '#6366F1'
        },
        'agent_shutdown': {
            icon: 'fa-power-off',
            gradient: 'linear-gradient(135deg, #4F46E5 0%, #4338CA 100%)',
            title: '🔴 Agent Shutdown',
            badge: 'bg-primary',
            borderColor: '#4338CA'
        },
        'agent_stopped': {
            icon: 'fa-stop-circle',
            gradient: 'linear-gradient(135deg, #94A3B8 0%, #64748B 100%)',
            title: '⏹️ Agent Stopped',
            badge: 'bg-secondary',
            borderColor: '#94A3B8'
        }
    };
    
    const config = eventConfig[eventType] || eventConfig['agent_shutdown'];
    
    // Build info cards for lifecycle data
    const infoCards = [];
    
    if (log.hostname || log.host_name) {
        infoCards.push(`
            <div class="lifecycle-info-item">
                <i class="fas fa-desktop text-primary"></i>
                <span><strong>Hostname:</strong> ${log.hostname || log.host_name}</span>
            </div>
        `);
    }
    
    if (log.ip_address) {
        infoCards.push(`
            <div class="lifecycle-info-item">
                <i class="fas fa-network-wired text-info"></i>
                <span><strong>IP Address:</strong> ${log.ip_address}</span>
            </div>
        `);
    }
    
    if (log.firewall_mode) {
        // The agent only emits `whitelist_only` now; legacy values from
        // older agents are shown with a neutral secondary tone.
        const modeClass = log.firewall_mode === 'whitelist_only'
            ? 'text-success'
            : 'text-secondary';
        infoCards.push(`
            <div class="lifecycle-info-item">
                <i class="fas fa-shield-alt ${modeClass}"></i>
                <span><strong>Firewall Mode:</strong> ${log.firewall_mode}</span>
            </div>
        `);
    }
    
    if (log.uptime) {
        infoCards.push(`
            <div class="lifecycle-info-item">
                <i class="fas fa-clock text-success"></i>
                <span><strong>Uptime:</strong> ${log.uptime}</span>
            </div>
        `);
    }
    
    if (log.agent_id) {
        infoCards.push(`
            <div class="lifecycle-info-item">
                <i class="fas fa-fingerprint text-secondary"></i>
                <span><strong>Agent ID:</strong> <code>${log.agent_id.substring(0, 12)}...</code></span>
            </div>
        `);
    }
    
    return `
        <div class="log-item lifecycle-event p-3 border-bottom" data-log-id="${logId}" 
             data-level="${(log.level || 'info').toLowerCase()}"
             data-agent="${agentHost.toLowerCase()}"
             style="border-left: 4px solid ${config.borderColor}; background: linear-gradient(90deg, rgba(255,255,255,0.95) 0%, rgba(248,249,250,1) 100%);">
            
            <div class="row align-items-center">
                <div class="col-auto">
                    <input type="checkbox" class="form-check-input log-checkbox" value="${logId}">
                </div>
                
                <div class="col-auto">
                    <div class="lifecycle-icon-wrapper" style="background: ${config.gradient}; width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 15px rgba(0,0,0,0.15);">
                        <i class="fas ${config.icon} fa-lg text-white"></i>
                    </div>
                </div>
                
                <div class="col">
                    <div class="d-flex align-items-center gap-2 mb-1">
                        <h6 class="mb-0 fw-bold">${config.title}</h6>
                        <span class="badge ${config.badge}">${eventType.replace('agent_', '').toUpperCase()}</span>
                    </div>
                    
                    <div class="d-flex align-items-center gap-3 text-muted small">
                        <span><i class="fas fa-calendar-alt me-1"></i>${formatTimestamp(log.timestamp)}</span>
                        <span><i class="fas fa-server me-1"></i>${agentHost}</span>
                    </div>
                    
                    ${log.message ? `
                        <div class="mt-2 p-2 rounded" style="background: rgba(0,0,0,0.03);">
                            <i class="fas fa-comment-alt me-2 text-muted"></i>
                            <span class="text-dark">${log.message}</span>
                        </div>
                    ` : ''}
                </div>
                
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-ellipsis-v"></i>
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="showLogDetails('${logId}')">
                                <i class="fas fa-info-circle me-2"></i>View Details
                            </a></li>
                            <li><a class="dropdown-item" href="#" onclick="exportSingleLog('${logId}')">
                                <i class="fas fa-download me-2"></i>Export
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="#" onclick="clearSingleLog('${logId}')">
                                <i class="fas fa-trash me-2"></i>Delete
                            </a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            ${infoCards.length > 0 ? `
                <div class="lifecycle-info-grid mt-3 pt-3 border-top" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px;">
                    ${infoCards.join('')}
                </div>
            ` : ''}
        </div>
    `;
}

// Helper. Delegated to SaintDate so every page renders timestamps the same
// way; the previous in-page impl used the same vi-VN locale already, so
// behaviour is unchanged. Local fallback covers the (rare) case where the
// shared script didn't load.
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    if (window.SaintDate) {
        return window.SaintDate.formatVNFull(timestamp) || timestamp.toString();
    }
    try {
        return new Date(timestamp).toLocaleString('vi-VN');
    } catch (e) {
        return timestamp.toString();
    }
}

function formatTime(timestamp) {
    if (!timestamp) return '00:00:00';
    try {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('vi-VN');
    } catch (e) {
        return '00:00:00';
    }
}
