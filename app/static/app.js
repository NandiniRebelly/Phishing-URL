/**
 * Phishing URL Detector - Frontend Application
 */

(function() {
    'use strict';

    const form = document.getElementById('check-form');
    const urlInput = document.getElementById('url-input');
    const checkBtn = document.getElementById('check-btn');
    const btnText = checkBtn.querySelector('.btn-text');
    const btnLoading = checkBtn.querySelector('.btn-loading');
    const resultsSection = document.getElementById('results');
    const errorSection = document.getElementById('error');
    const errorMessage = document.getElementById('error-message');

    // Result elements
    const meterFill = document.getElementById('meter-fill');
    const scoreNumber = document.getElementById('score-number');
    const riskLevel = document.getElementById('risk-level');
    const normalizedUrl = document.getElementById('normalized-url');
    const reasonsList = document.getElementById('reasons-list');
    const intelSources = document.getElementById('intel-sources');
    const intelNote = document.getElementById('intel-note');
    const signalsList = document.getElementById('signals-list');

    /**
     * Set loading state
     */
    function setLoading(loading) {
        checkBtn.disabled = loading;
        btnText.hidden = loading;
        btnLoading.hidden = !loading;
    }

    /**
     * Hide all result sections
     */
    function hideResults() {
        resultsSection.classList.add('hidden');
        errorSection.classList.add('hidden');
    }

    /**
     * Show error message
     */
    function showError(message) {
        hideResults();
        errorMessage.textContent = message;
        errorSection.classList.remove('hidden');
    }

    /**
     * Render threat intelligence sources
     */
    function renderIntelSources(intel) {
        intelSources.innerHTML = '';
        intelNote.textContent = '';
        
        if (!intel || !intel.sources) {
            return;
        }
        
        let hasBlockedByRobots = false;
        
        intel.sources.forEach(function(source) {
            const div = document.createElement('div');
            div.className = 'intel-source';
            
            const indicator = document.createElement('span');
            indicator.className = 'status-indicator ' + source.result;
            
            const name = document.createElement('span');
            name.className = 'source-name';
            name.textContent = source.name;
            
            const status = document.createElement('span');
            status.className = 'source-status';
            
            // Map result values to unambiguous UI labels
            switch(source.result) {
                case 'hit':
                    status.textContent = 'HIT';
                    status.classList.add('status-hit');
                    break;
                case 'clear':
                    status.textContent = 'CLEAR';
                    status.classList.add('status-clear');
                    break;
                case 'disabled':
                    status.textContent = 'DISABLED';
                    status.classList.add('status-disabled');
                    break;
                case 'blocked_by_robots':
                    status.textContent = 'BLOCKED';
                    status.classList.add('status-blocked');
                    hasBlockedByRobots = true;
                    break;
                case 'unavailable':
                    status.textContent = 'UNAVAILABLE';
                    status.classList.add('status-unavailable');
                    break;
                default:
                    // Fallback - should never happen
                    status.textContent = source.result.toUpperCase();
            }
            
            div.appendChild(indicator);
            div.appendChild(name);
            div.appendChild(status);
            
            // Add tooltip with note if available
            if (source.note) {
                div.title = source.note;
            }
            
            intelSources.appendChild(div);
        });
        
        // Add note if any source is blocked by robots.txt
        if (hasBlockedByRobots) {
            intelNote.textContent = 'Some sources are blocked due to robots.txt policy restrictions.';
        } else if (intel.known_bad && intel.feed_hits && intel.feed_hits.length > 0) {
            intelNote.textContent = 'URL found in threat intelligence feeds - exercise extreme caution.';
        }
    }

    /**
     * Render signals checked
     */
    function renderSignals(signals) {
        signalsList.innerHTML = '';
        
        if (!signals || !Array.isArray(signals)) {
            return;
        }
        
        signals.forEach(function(signal) {
            const span = document.createElement('span');
            span.className = 'signal-tag';
            span.textContent = signal;
            signalsList.appendChild(span);
        });
    }

    /**
     * Show analysis results
     */
    function showResults(data) {
        hideResults();

        // Update score display
        const score = data.score;
        scoreNumber.textContent = score;

        // Update meter
        meterFill.style.width = score + '%';
        meterFill.className = 'meter-fill ' + data.risk.toLowerCase();

        // Update risk level badge
        riskLevel.textContent = data.risk + ' Risk';
        riskLevel.className = 'risk-level ' + data.risk.toLowerCase();

        // Update normalized URL
        normalizedUrl.textContent = data.normalized_url;

        // Update reasons list
        reasonsList.innerHTML = '';
        data.reasons.forEach(function(reason) {
            const li = document.createElement('li');
            li.textContent = reason;
            
            // Add appropriate styling based on content
            if (reason.toLowerCase().includes('no obvious') || 
                reason.toLowerCase().includes('not detected')) {
                li.classList.add('safe');
            } else if (reason.toUpperCase().includes('KNOWN MALICIOUS')) {
                li.classList.add('danger');
            } else if (data.risk === 'High') {
                li.classList.add('danger');
            } else if (data.risk === 'Medium') {
                li.classList.add('warning');
            }
            
            reasonsList.appendChild(li);
        });

        // Render threat intel sources
        renderIntelSources(data.intel);
        
        // Render signals checked
        renderSignals(data.signals_checked);

        resultsSection.classList.remove('hidden');
    }

    /**
     * Submit URL for analysis
     */
    async function analyzeUrl(url) {
        setLoading(true);
        hideResults();

        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'An error occurred');
            }

            showResults(data);
        } catch (err) {
            if (err.name === 'TypeError') {
                showError('Network error. Please check your connection.');
            } else {
                showError(err.message || 'An unexpected error occurred');
            }
        } finally {
            setLoading(false);
        }
    }

    /**
     * Handle form submission
     */
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to analyze');
            return;
        }

        analyzeUrl(url);
    });

    /**
     * Clear results when input changes significantly
     */
    urlInput.addEventListener('input', function() {
        // Optional: hide results when user starts typing a new URL
        // hideResults();
    });

    // Focus input on page load
    urlInput.focus();

})();
