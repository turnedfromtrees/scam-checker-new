/**
 * Main Application Logic
 * Handles UI interactions and displays results
 */

(function() {
    'use strict';

    // Safety banner messages
    const safetyMessages = [
        "Your bank will NEVER ask for your PIN",
        "Never give remote access to your computer to strangers",
        "If it sounds too good to be true, it probably is",
        "Legitimate companies don't ask for payment in gift cards",
        "Check the sender's email address — scammers spoof real companies",
        "Government agencies don't threaten arrest over email"
    ];

    let bannerIndex = 0;
    let bannerInterval;

    /**
     * Initialize the application
     */
    function init() {
        // Set up event listeners
        const analyzeBtn = document.getElementById('analyze-btn');
        const clearBtn = document.getElementById('clear-btn');
        const emailInput = document.getElementById('email-input');

        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', handleAnalyze);
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', handleClear);
        }

        if (emailInput) {
            emailInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                    handleAnalyze();
                }
            });
        }

        // Start rotating safety banners
        startBannerRotation();

        // Add some sample emails for testing
        addSampleEmails();
    }

    /**
     * Start rotating safety banner messages
     */
    function startBannerRotation() {
        const bannerText = document.getElementById('banner-text');
        if (!bannerText) return;

        // Update every 8 seconds
        bannerInterval = setInterval(() => {
            bannerIndex = (bannerIndex + 1) % safetyMessages.length;
            
            // Fade out
            bannerText.style.opacity = '0';
            
            setTimeout(() => {
                bannerText.textContent = safetyMessages[bannerIndex];
                bannerText.style.opacity = '1';
            }, 300);
        }, 8000);

        // Add transition style
        bannerText.style.transition = 'opacity 0.3s ease';
    }

    /**
     * Handle analyze button click
     */
    function handleAnalyze() {
        const emailInput = document.getElementById('email-input');
        const resultsSection = document.getElementById('results-section');
        const analyzeBtn = document.getElementById('analyze-btn');

        if (!emailInput || !emailInput.value.trim()) {
            showError('Please paste the email text to analyze.');
            return;
        }

        // Show loading state
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = 'Analyzing...';
        resultsSection.style.display = 'block';

        // Analyze the email
        const results = ScamDetector.analyze(emailInput.value);

        // Display results
        displayResults(results);

        // Show completion state on button
        analyzeBtn.textContent = 'Done ✓';
        analyzeBtn.style.background = '#10b981';
        analyzeBtn.style.color = 'white';

        // Show "Analysis Complete" notification
        showAnalysisComplete(results.riskLevel);

        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Reset button after 2 seconds
        setTimeout(() => {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = 'Analyze Email';
            analyzeBtn.style.background = '';
            analyzeBtn.style.color = '';
        }, 2000);
    }

    /**
     * Handle clear button click
     */
    function handleClear() {
        const emailInput = document.getElementById('email-input');
        const resultsSection = document.getElementById('results-section');
        const analyzeBtn = document.getElementById('analyze-btn');

        // Clear input
        emailInput.value = '';
        
        // Hide results
        resultsSection.style.display = 'none';
        
        // Reset button state (fix for "Analyzing..." stuck bug)
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = 'Analyze Email';
        }
        
        emailInput.focus();
    }

    /**
     * Display analysis results
     */
    function displayResults(results) {
        // Update risk indicator
        const riskIndicator = document.getElementById('risk-indicator');
        const riskLevel = document.getElementById('risk-level');
        const riskScore = document.getElementById('risk-score');

        // Remove old risk classes
        riskIndicator.classList.remove('high', 'medium', 'low', 'unknown');
        
        // Add appropriate class
        const levelClass = results.riskLevel.toLowerCase().replace(' ', '-');
        riskIndicator.classList.add(levelClass);

        // Update text
        riskLevel.textContent = results.riskLevel + ' RISK';
        riskScore.textContent = `Score: ${results.score}/100`;

        // Display red flags
        const flagsList = document.getElementById('flags-list');
        flagsList.innerHTML = '';

        if (results.redFlags.length === 0) {
            flagsList.innerHTML = '<li style="border-left-color: #10b981; background: rgba(16, 185, 129, 0.1);">No significant red flags detected. This does NOT mean the email is safe.</li>';
        } else {
            for (const flag of results.redFlags) {
                for (const match of flag.matches) {
                    const li = document.createElement('li');
                    li.innerHTML = `<span class="flag-icon">⚠️</span><strong>${flag.category}:</strong> "${escapeHtml(match.match)}"${match.context ? `<br><small style="color: #94a3b8;">${escapeHtml(match.context)}</small>` : ''}`;
                    flagsList.appendChild(li);
                }
            }
        }

        // Display matched patterns by category
        displayMatchedPatterns(results.matchedPatterns);
    }

    /**
     * Display matched patterns organized by category
     */
    function displayMatchedPatterns(matchedPatterns) {
        const categories = ['urgency', 'links', 'requests', 'spoofing', 'threats', 'emotional'];
        
        for (const category of categories) {
            const container = document.getElementById(`${category}-patterns`);
            if (!container) continue;

            container.innerHTML = '';

            if (matchedPatterns[category]) {
                const pattern = matchedPatterns[category];
                
                // Add category heading
                const heading = document.createElement('h4');
                heading.textContent = `${pattern.name} (${pattern.weight} pts each)`;
                container.appendChild(heading);

                // Add matched items as tags
                const matchesDiv = document.createElement('div');
                for (const match of pattern.matches) {
                    const tag = document.createElement('span');
                    tag.className = 'pattern-match';
                    tag.textContent = match;
                    matchesDiv.appendChild(tag);
                }
                container.appendChild(matchesDiv);
            }
        }
    }

    /**
     * Show analysis complete notification
     */
    function showAnalysisComplete(riskLevel) {
        const notification = document.createElement('div');
        
        // Color based on risk level
        let bgColor, icon;
        if (riskLevel === 'HIGH') {
            bgColor = '#dc2626';
            icon = '🚨';
        } else if (riskLevel === 'MEDIUM') {
            bgColor = '#f59e0b';
            icon = '⚠️';
        } else if (riskLevel === 'LOW') {
            bgColor = '#3b82f6';
            icon = 'ℹ️';
        } else {
            bgColor = '#10b981';
            icon = '✓';
        }
        
        notification.innerHTML = `
            <span style="font-size: 1.5rem; margin-right: 0.5rem;">${icon}</span>
            <span>Analysis Complete</span>
        `;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: ${bgColor};
            color: white;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            z-index: 1000;
            display: flex;
            align-items: center;
            font-weight: 500;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            animation: slideDown 0.3s ease;
        `;
        
        // Add animation keyframes if not already present
        if (!document.getElementById('analysis-complete-styles')) {
            const style = document.createElement('style');
            style.id = 'analysis-complete-styles';
            style.textContent = `
                @keyframes slideDown {
                    from { opacity: 0; transform: translateX(-50%) translateY(-20px); }
                    to { opacity: 1; transform: translateX(-50%) translateY(0); }
                }
                @keyframes fadeOut {
                    from { opacity: 1; }
                    to { opacity: 0; }
                }
            `;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(notification);

        // Remove after 2.5 seconds
        setTimeout(() => {
            notification.style.animation = 'fadeOut 0.3s ease forwards';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 2500);
    }

    /**
     * Show error message
     */
    function showError(message) {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = 'toast-error';
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #dc2626;
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            z-index: 1000;
            animation: fadeIn 0.3s ease;
        `;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 3000);
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Add sample emails for quick testing
     */
    function addSampleEmails() {
        // Sample emails can be loaded from a dropdown or used for demo
        window.sampleScamEmails = [
            {
                name: "Phishing - Amazon Account",
                text: `From: support@amaz0n-security.com
Subject: URGENT: Your account will be suspended!

Dear Customer,

We have detected unusual activity on your Amazon account. Your account will be permanently suspended within 24 hours unless you verify your identity immediately.

Click here to verify: https://amazon-verify.secure-login.ga/confirm

Failure to respond will result in permanent account deletion.

Amazon Security Team`
            },
            {
                name: "IRS Scam",
                text: `From: irs-notices@irs-gov.us
Subject: FINAL NOTICE: Legal Action Pending

Dear Taxpayer,

This is your final notice. You owe $4,582.00 in back taxes. If you do not pay immediately, you will face criminal prosecution and possible arrest.

The FBI has been notified of your case. To avoid arrest, you must purchase Google Play gift cards in the amount of $4,582.00 and provide the codes to our agent.

Call us immediately at 1-800-XXX-XXXX or face legal consequences.

IRS Criminal Investigation Division`
            },
            {
                name: "Tech Support Scam",
                text: `From: Microsoft Security Team <security@microsoft-support.xyz>
Subject: Your computer has been infected!

Dear User,

Our systems have detected that your computer is infected with multiple viruses. Your personal data is at risk.

To remove the viruses, please call our toll-free number: 1-800-XXX-XXXX

A certified technician will guide you through the removal process. You may need to grant remote access to your computer.

Failure to act now will result in complete data loss.

Microsoft Security Team`
            },
            {
                name: "Romance Scam",
                text: `From: james_smith22@gmail.com
Subject: Hello dear

Hello my dear friend,

I am James Smith, a contractor working in Nigeria. I am currently stranded and need your help urgently.

I have $2.5 million USD that I need to transfer out of the country. If you help me, I will give you 30% of the money.

Please send me your bank account details and I will transfer the funds immediately. This is completely safe and legal.

Kindly respond as soon as possible. I am counting on you.

Best regards,
James`
            },
            {
                name: "Prize Scam",
                text: `From: Winner Notification <prize@lottery-int.net>
Subject: CONGRATULATIONS! You've Won $1,000,000!

CONGRATULATIONS!!!

You have been selected as the winner of our international lottery! Your prize is $1,000,000.00 USD.

To claim your prize, you must send $500 as a processing fee via Western Union to our claims agent.

This offer expires in 48 hours. Act now or lose your winnings forever!

Click here to claim your prize: http://192.168.1.100/claim

Lottery International`
            }
        ];
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();