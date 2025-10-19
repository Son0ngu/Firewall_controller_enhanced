(function () {
    // Simple connection test
    try {
        const socket = io();

        socket.on('connect', function () {
            console.log(' Connected to server for real-time updates');

            const statusDot = document.querySelector('.pulse-dot');
            if (statusDot) {
                statusDot.style.background = '#28a745';
            }
        });

        socket.on('disconnect', function () {
            console.log(' Disconnected from server');

            const statusDot = document.querySelector('.pulse-dot');
            if (statusDot) {
                statusDot.style.background = '#dc3545';
            }
        });

        socket.on('stats_update', function (statsData) {
            console.log(' Stats update received:', statsData);
            updateDashboardStats(statsData);
        });
    } catch (error) {
        console.log('Socket.IO not available:', error);
    }

    function updateDashboardStats(stats) {
        console.log(' Updating dashboard stats:', stats);
        
        // More specific selectors for each stat card
        const totalLogsEl = document.querySelector('[id*="total"]') || document.querySelectorAll('.stat-number')[0];
        const allowedEl = document.querySelector('[id*="allowed"]') || document.querySelectorAll('.stat-number')[1];
        const blockedEl = document.querySelector('[id*="blocked"]') || document.querySelectorAll('.stat-number')[2];
        const activeAgentsEl = document.querySelector('[id*="agent"]') || document.querySelectorAll('.stat-number')[3];

        if (totalLogsEl && stats.total_logs !== undefined) {
            animateNumber(totalLogsEl, parseInt(totalLogsEl.textContent.replace(/,/g, ''), 10) || 0, stats.total_logs);
        }
        
        if (allowedEl && stats.allowed_count !== undefined) {
            animateNumber(allowedEl, parseInt(allowedEl.textContent.replace(/,/g, ''), 10) || 0, stats.allowed_count);
        }
        
        if (blockedEl && stats.blocked_count !== undefined) {
            animateNumber(blockedEl, parseInt(blockedEl.textContent.replace(/,/g, ''), 10) || 0, stats.blocked_count);
        }
        
        if (activeAgentsEl && stats.active_agents !== undefined) {
            animateNumber(activeAgentsEl, parseInt(activeAgentsEl.textContent.replace(/,/g, ''), 10) || 0, stats.active_agents);
        }
    }

    function animateNumber(element, start, end) {
        const duration = 1000;
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const current = Math.floor(start + (end - start) * progress);
            element.textContent = current.toLocaleString();

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    // Load initial statistics
    async function loadDashboardStats() {
        try {
            console.log(' Loading dashboard statistics...');
            
            const response = await fetch('/api/logs/stats');
            if (response.ok) {
                const data = await response.json();
                console.log(' Dashboard stats loaded:', data);
                
                if (data.success) {
                    updateDashboardStats({
                        total_logs: data.total || 0,
                        allowed_count: data.allowed || 0,
                        blocked_count: data.blocked || 0,
                        active_agents: 0 // Will be updated separately
                    });
                }
            }
            
            // Load active agents count
            const agentsResponse = await fetch('/api/agents/statistics');
            if (agentsResponse.ok) {
                const agentsData = await agentsResponse.json();
                console.log(' Agents stats loaded:', agentsData);
                
                if (agentsData.success && agentsData.data) {
                    const activeAgentsEl = document.querySelector('[id*="agent"]') || document.querySelectorAll('.stat-number')[3];
                    if (activeAgentsEl) {
                        animateNumber(activeAgentsEl, parseInt(activeAgentsEl.textContent.replace(/,/g, ''), 10) || 0, agentsData.data.active || 0);
                    }
                }
            }
        } catch (error) {
            console.error(' Error loading dashboard stats:', error);
        }
    }

    setInterval(function () {
        location.reload();
    }, 30000);

    document.addEventListener('DOMContentLoaded', function () {
        console.log(' Dashboard initialized');
        
        // Load initial stats
        loadDashboardStats();
        
        // Animate cards
        const cards = document.querySelectorAll('.status-card, .feature-card');
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';

            setTimeout(() => {
                card.style.transition = 'all 0.6s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
        
        // Refresh stats every 10 seconds
        setInterval(loadDashboardStats, 10000);
    });
})();