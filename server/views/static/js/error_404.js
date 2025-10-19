// Auto-redirect suggestion after 30 seconds
let countdown = 30;
let redirectTimer;

function startRedirectCountdown() {
    const countdownElement = document.createElement('div');
    countdownElement.className = 'alert alert-info mt-4';
    countdownElement.innerHTML = `
        <i class="fas fa-info-circle me-2"></i>
        <span id="countdown-text">Redirecting to dashboard in ${countdown} seconds...</span>
        <button type="button" class="btn btn-sm btn-outline-info ms-2" onclick="cancelRedirect()">
            Cancel
        </button>
    `;
    
    document.querySelector('.error-page .container').appendChild(countdownElement);
    
    redirectTimer = setInterval(() => {
        countdown--;
        document.getElementById('countdown-text').textContent = 
            `Redirecting to dashboard in ${countdown} seconds...`;
        
        if (countdown <= 0) {
            window.location.href = '/';
        }
    }, 1000);
}

function cancelRedirect() {
    clearInterval(redirectTimer);
    const countdownElement = document.querySelector('.alert-info');
    if (countdownElement) {
        countdownElement.remove();
    }
}

// Start countdown after 10 seconds on page
setTimeout(startRedirectCountdown, 10000);

// Track 404 errors for analytics (optional)
if (typeof gtag !== 'undefined') {
    gtag('event', 'page_not_found', {
        'page_location': window.location.href,
        'page_title': document.title
    });
}

console.log('404 Error: Page not found -', window.location.href);