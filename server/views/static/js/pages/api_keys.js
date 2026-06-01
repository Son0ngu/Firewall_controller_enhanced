/**
 * api_keys.js — page logic for /api-keys.
 *
 * Migrated to shared core: every server call goes through ``SaintAPI``,
 * toast notifications through ``SaintToast``, dates through ``SaintDate``.
 * The page no longer carries its own copies of those helpers.
 *
 * Loaded by ``server/views/templates/api_keys.html`` via a ``<script src>``
 * include; the template itself is markup-only.
 */

let allKeys = [];
let keyToRevoke = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
  loadApiKeys();
  setupFilters();
  setupSocket();

  // Initialize Custom Selects
  if (window.initCustomSelect) {
    window.initCustomSelect('filterStatus');
    window.initCustomSelect('filterPermission');
    window.initCustomSelect('keyExpiry');
  }
});

// Setup WebSocket for real-time updates
function setupSocket() {
  if (typeof io !== 'undefined') {
    const socket = io();
    socket.on('api_key_created', () => loadApiKeys());
    socket.on('api_key_revoked', () => loadApiKeys());
    socket.on('api_key_deleted', () => loadApiKeys());
  }
}

// Setup filter listeners
function setupFilters() {
  const searchKeys = document.getElementById('searchKeys');
  const filterStatus = document.getElementById('filterStatus');
  const filterPermission = document.getElementById('filterPermission');
  if (searchKeys) searchKeys.addEventListener('input', filterKeys);
  if (filterStatus) filterStatus.addEventListener('change', filterKeys);
  if (filterPermission) filterPermission.addEventListener('change', filterKeys);
}

// Load API keys from server
async function loadApiKeys() {
  try {
    const result = await SaintAPI.get('/api/api-keys');

    if (result && result.success) {
      // Keys are directly in result, not result.data
      allKeys = result.keys || [];

      // Calculate stats from keys
      const keyStatuses = allKeys.map((key) => getKeyStatus(key));
      const stats = {
        total: allKeys.length,
        active: keyStatuses.filter((status) => status === 'active' || status === 'expiring').length,
        revoked: keyStatuses.filter((status) => status === 'revoked').length,
        expiring_soon: keyStatuses.filter((status) => status === 'expiring').length,
      };

      updateStats(stats);
      renderKeys(allKeys);
    } else {
      SaintToast.error((result && result.error) || 'Error loading API keys');
    }
  } catch (error) {
    console.error('Error loading keys:', error);
    SaintToast.error(error.message || 'Failed to load API keys');
  }
}

// Update statistics cards
function updateStats(stats) {
  setText('totalKeys', stats.total || 0);
  setText('activeKeys', stats.active || 0);
  setText('revokedKeys', stats.revoked || 0);
  setText('expiringKeys', stats.expiring_soon || 0);
}

// Filter keys based on search and filters
function filterKeys() {
  const search = (document.getElementById('searchKeys')?.value || '').toLowerCase();
  const status = document.getElementById('filterStatus')?.value || 'all';
  const permission = document.getElementById('filterPermission')?.value || 'all';

  const filtered = allKeys.filter((key) => {
    if (search && !key.name.toLowerCase().includes(search)) return false;
    if (status !== 'all') {
      const keyStatus = getKeyStatus(key);
      if (keyStatus !== status) return false;
    }
    if (permission !== 'all') {
      if (!key.permissions || !key.permissions.includes(permission)) return false;
    }
    return true;
  });

  renderKeys(filtered);
}

// Get key status: 'active', 'expiring', 'expired', or 'revoked'
function getKeyStatus(key) {
  if (!key.is_active) return 'revoked';
  if (key.expires_at) {
    const daysUntil = (new Date(key.expires_at) - new Date()) / (1000 * 60 * 60 * 24);
    if (daysUntil <= 0) return 'expired';
    if (daysUntil <= 7) return 'expiring';
  }
  return 'active';
}

// Render keys list
function renderKeys(keys) {
  const container = document.getElementById('keysContainer');
  if (!container) return;

  if (keys.length === 0) {
    container.innerHTML = `
      <div class="col-12">
        <div class="empty-state text-center py-5">
          <div class="empty-state-icon mx-auto mb-3">
            <i class="fas fa-key"></i>
          </div>
          <h5 class="mb-2">No API keys found</h5>
          <p class="text-muted mb-0">Create a key to allow agents to register and sync with this server.</p>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = keys.map((key) => renderKeyCard(key)).join('');
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

// Render single key card
function renderKeyCard(key) {
  const status = getKeyStatus(key);
  const statusColors = {
    active: 'success',
    revoked: 'danger',
    expiring: 'warning',
    expired: 'secondary',
  };
  const statusIcons = {
    active: 'check-circle',
    revoked: 'ban',
    expiring: 'exclamation-triangle',
    expired: 'clock',
  };
  const cardStateClass = status === 'revoked' || status === 'expired' ? status : '';

  return `
    <div class="col-lg-6 col-xl-4">
      <div class="card key-card ${cardStateClass}">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-start mb-3">
            <h6 class="card-title mb-0 fw-bold">
              <i class="fas fa-key text-primary me-2"></i>${escapeHtml(key.name)}
            </h6>
            <span class="badge bg-${statusColors[status]}">
              <i class="fas fa-${statusIcons[status]} me-1"></i>${status}
            </span>
          </div>

          ${key.description ? `<p class="text-muted small mb-2">${escapeHtml(key.description)}</p>` : ''}

          <div class="mb-3">
            <small class="text-muted d-block">Permissions:</small>
            <div class="permissions-list">
              ${(key.permissions || []).map((p) => `<span class="permission-tag">${formatPermission(p)}</span>`).join('')}
            </div>
          </div>

          <div class="row g-2 mb-3">
            <div class="col-6">
              <div class="key-metric">
                <small class="text-muted">Usage</small>
                <div class="fw-bold">${key.usage_count || 0}</div>
              </div>
            </div>
            <div class="col-6">
              <div class="key-metric">
                <small class="text-muted">Created</small>
                <div class="fw-bold small">${SaintDate.formatVN(key.created_at) || 'N/A'}</div>
              </div>
            </div>
          </div>

          <div class="d-flex justify-content-between text-muted small mb-2">
            ${key.expires_at ? `<span><i class="fas fa-clock me-1"></i>${SaintDate.formatVN(key.expires_at) || 'N/A'}</span>` : '<span>No expiry</span>'}
            ${key.last_used_at ? `<span>Last: ${SaintDate.formatVN(key.last_used_at) || 'N/A'}</span>` : ''}
          </div>

        </div>

        <div class="card-footer bg-transparent border-0 pt-0 key-actions">
          ${key.is_active ? `
          <button class="btn btn-sm btn-outline-danger w-100" onclick="showRevokeModal('${key._id}', '${escapeHtml(key.name)}')">
            <i class="fas fa-ban me-1"></i>Revoke Key
          </button>
          ` : `
          <button class="btn btn-sm btn-outline-secondary w-100" onclick="deleteKey('${key._id}')">
            <i class="fas fa-trash me-1"></i>Delete Key
          </button>
          `}
        </div>
      </div>
    </div>
  `;
}

// Format permission name
function formatPermission(perm) {
  const names = {
    agent_register: 'Register',
    agent_read: 'Read',
    whitelist_sync: 'Whitelist',
    logs_write: 'Logs',
    admin: 'Admin',
  };
  return names[perm] || perm;
}

// Delegate to the shared helper (see server/views/static/js/core/utils.js).
const escapeHtml = (value) => window.SaintUtils.escapeHtml(value);

// Create new API key
async function createApiKey() {
  const name = document.getElementById('keyName').value.trim();
  if (!name) {
    SaintToast.warning('Please enter a key name');
    return;
  }

  const expiryDays = parseInt(document.getElementById('keyExpiry').value, 10);

  try {
    const result = await SaintAPI.post('/api/api-keys', {
      name,
      description: document.getElementById('keyDescription').value.trim(),
      expires_in_days: expiryDays,
    });

    if (result && result.success) {
      bootstrap.Modal.getInstance(document.getElementById('newKeyModal')).hide();
      // Show the generated key — api_key is directly in result
      document.getElementById('generatedKey').textContent = result.api_key;
      new bootstrap.Modal(document.getElementById('showKeyModal')).show();
      document.getElementById('createKeyForm').reset();
    } else {
      SaintToast.error((result && result.error) || 'Failed to create API key');
    }
  } catch (error) {
    console.error('Error creating key:', error);
    SaintToast.error(error.message || 'Failed to create API key');
  }
}

// Copy API key to clipboard
async function copyApiKey() {
  const key = document.getElementById('generatedKey').textContent;
  try {
    await navigator.clipboard.writeText(key);
    SaintToast.success('API key copied to clipboard!');
  } catch (error) {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = key;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    SaintToast.success('API key copied to clipboard!');
  }
}

// Close modal and refresh list
function closeAndRefresh() {
  bootstrap.Modal.getInstance(document.getElementById('showKeyModal')).hide();
  loadApiKeys();
}

// Show revoke confirmation modal
function showRevokeModal(keyId, keyName) {
  keyToRevoke = keyId;
  document.getElementById('revokeKeyName').textContent = keyName;
  document.getElementById('confirmRevokeBtn').onclick = () => revokeKey(keyId);
  new bootstrap.Modal(document.getElementById('revokeModal')).show();
}

// Revoke API key
async function revokeKey(keyId) {
  try {
    const result = await SaintAPI.post(`/api/api-keys/${keyId}/revoke`, {
      reason: 'Revoked by admin',
    });

    if (result && result.success) {
      bootstrap.Modal.getInstance(document.getElementById('revokeModal')).hide();
      SaintToast.success('API key revoked successfully');
      loadApiKeys();
    } else {
      SaintToast.error((result && result.error) || 'Failed to revoke API key');
    }
  } catch (error) {
    console.error('Error revoking key:', error);
    SaintToast.error(error.message || 'Failed to revoke API key');
  }
}

// Delete API key
async function deleteKey(keyId) {
  if (!confirm('Are you sure you want to delete this API key permanently?')) return;

  try {
    const result = await SaintAPI.del(`/api/api-keys/${keyId}`);
    // DELETE may return null on 204, or {success: true, ...}
    if (result === null || (result && result.success)) {
      SaintToast.success('API key deleted successfully');
      loadApiKeys();
    } else {
      SaintToast.error((result && result.error) || 'Failed to delete API key');
    }
  } catch (error) {
    console.error('Error deleting key:', error);
    SaintToast.error(error.message || 'Failed to delete API key');
  }
}
