/**
 * Scam Detection Engine
 * Analyzes email text for common scam patterns and red flags
 */

const ScamDetector = (function() {
    'use strict';

    // Pattern definitions with weights
    // weight is now per-match (was per-category)
    const patterns = {
        urgency: {
            weight: 8,
            name: "Urgency Language",
            maxScore: 30,
            patterns: [
                /\bact now\b/i,
                /\bimmediate(?:ly)?\b/i,
                /\burgent(?:ly)?\b/i,
                /\blimited time\b/i,
                /\bexpires?\s+(?:today|soon|in \d+ hours?|within \d+ hours?)\b/i,
                /\brespond\s+(?:immediately|right away|today)\b/i,
                /\btime sensitive\b/i,
                /\bdon'?t (?:wait|delay)\b/i,
                /\bfinal notice\b/i,
                /\blast (?:chance|warning|reminder)\b/i,
                /\bwithin 24 hours?\b/i,
                /\bbefore it'?s too late\b/i,
                /\bdeadline\b/i,
                /\bfailure to .*(?:result|lead|cause)\b/i,
                /\bexpired\b/i,
                /\brenew(?:al)?\s+(?:today|now|immediately)\b/i,
                /\byour\s+(?:subscription|protection|security)\s+(?:has\s+)?expired\b/i,
                /\bsave\s+\d+%.*renew\b/i
            ]
        },

        links: {
            weight: 10,
            name: "Suspicious Links",
            maxScore: 40,
            patterns: [
                /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,  // IP address URLs
                /https?:\/\/[^\s]*\.(?:ly|io|ga|cf|ml|gq|tk|pw|ru|cn|br)[^\s]*/i,  // Suspicious TLDs
                /https?:\/\/[^\s]*(?:bit\.ly|tinyurl|t\.co|is\.gd|v\.gd|ow\.ly|goo\.gl|shorturl)/i,  // URL shorteners
                /https?:\/\/[^\s]*@[^\s]*/i,  // URLs with @ (credential harvesting)
                /https?:\/\/[^\s]*\.(?:p?html?|php|aspx?)[^\s]*\?/i,  // Suspicious query params
                /\bclick here\b/i,
                /\bclick below\b/i,
                /\bfollow this link\b/i,
                /https?:\/\/[^\s]*(?:secure|login|verify|account|update|confirm)[^\s]*\.(?!com|org|gov|edu|mil)/i
            ]
        },

        requests: {
            weight: 12,
            name: "Suspicious Requests",
            maxScore: 50,
            patterns: [
                /\bwire\s+(?:money|transfer|funds?)\b/i,
                /\bgift\s*cards?\b/i,
                /\biTunes?\b.*card/i,
                /\bGoogle Play\b.*card/i,
                /\bAmazon\b.*card/i,
                /\bSteam\b.*card/i,
                /\bwire\s*transfer\b/i,
                /\bWestern\s*Union\b/i,
                /\bMoneyGram\b/i,
                /\bBitcoin\b/i,
                /\bcryptocurrency\b/i,
                /\bsend\s+(?:money|cash|payment)\b/i,
                /\bpassword\b/i,
                /\bPIN\b/,
                /\bsecurity\s*code\b/i,
                /\bverification\s*code\b/i,
                /\bCVV\b/i,
                /\bsocial\s*security\b/i,
                /\bSSN\b/i,
                /\bbank\s*account\b/i,
                /\brouting\s*number\b/i,
                /\bremote\s*access\b/i,
                /\bTeamViewer\b/i,
                /\bAnyDesk\b/i,
                /\binstall\s+(?:software|program|application)\b/i
            ]
        },

        spoofing: {
            weight: 10,
            name: "Sender Spoofing",
            maxScore: 40,
            patterns: [
                /[\w.-]+@[\w.-]*(?:0|O)[\w.-]*(?:amazon|apple|paypal|microsoft|google|facebook|netflix|bank)/i,
                /[\w.-]+@[\w.-]*(?:1|l)[\w.-]*(?:amazon|apple|paypal|microsoft|google|facebook|netflix|bank)/i,
                /[\w.-]*@(?!amazon\.com).*amazon/i,
                /[\w.-]*@(?!apple\.com).*apple/i,
                /[\w.-]*@(?!paypal\.com).*paypal/i,
                /[\w.-]*@(?!microsoft\.com).*microsoft/i,
                /[\w.-]*@(?!google\.com).*google/i,
                /[\w.-]*@(?!facebook\.com).*facebook/i,
                /[\w.-]*@(?!netflix\.com).*netflix/i,
                /[\w.-]*@(?!irs\.gov).*irs/i,
                /[\w.-]*@(?!socialsecurity\.gov).*social\s*security/i,
                /support@(?!amazon\.com|apple\.com|paypal\.com|microsoft\.com|google\.com|facebook\.com|netflix\.com|irs\.gov|chase\.com|wellsfargo\.com|bankofamerica\.com|citibank\.com)/i,
                /admin@(?!amazon\.com|apple\.com|paypal\.com|microsoft\.com|google\.com|facebook\.com|netflix\.com|irs\.gov|chase\.com|wellsfargo\.com|bankofamerica\.com|citibank\.com)/i,
                /security@(?!amazon\.com|apple\.com|paypal\.com|microsoft\.com|google\.com|facebook\.com|netflix\.com|irs\.gov|chase\.com|wellsfargo\.com|bankofamerica\.com|citibank\.com)/i,
                /billing@(?!amazon\.com|apple\.com|paypal\.com|microsoft\.com|google\.com|facebook\.com|netflix\.com|irs\.gov|chase\.com|wellsfargo\.com|bankofamerica\.com|citibank\.com)/i,
                /\.(?:co|com|net|org)\.[a-z]{2}$/i  // Suspicious double TLD
            ]
        },

        threats: {
            weight: 10,
            name: "Threatening Language",
            maxScore: 40,
            patterns: [
                /\blegal\s*action\b/i,
                /\blawsuit\b/i,
                /\barrest(?:ed)?\b/i,
                /\bcriminal\b/i,
                /\bprosecution\b/i,
                /\bjail\b/i,
                /\bprison\b/i,
                /\bFBI\b/i,
                /\bpolice\b/i,
                /\bsheriff\b/i,
                /\bdeportation\b/i,
                /\baccount\s*(?:will be |has been )?(?:suspend|terminat|close|lock)/i,
                /\baccount\s*(?:is|will be)\s+(?:locked|frozen|restricted)/i,
                /\bfreeze\s+(?:your\s+)?assets?\b/i,
                /\bblock\b.*\baccount\b/i,
                /\bpermanently\s+(?:suspend|close|delete)\b/i,
                /\bterminate\s+(?:your\s+)?account\b/i,
                /\bunauthorized\s+(?:access|transaction|activity)/i,
                /\byour\s+(?:device|computer|system)\s+(?:is|is no longer)\s+(?:not|no longer)\s+receiving\b/i,
                /\bprotection\s+(?:inactive|disabled|expired)\b/i,
                /\bsecurity\s+(?:subscription|protection)\s+(?:has\s+)?expired\b/i,
                /\bcritical\s+(?:security\s+)?updates?\b/i,
                /\bdata\s+loss\b/i,
                /\bmalware\s+(?:threats?|protection)\b/i
            ]
        },

        emotional: {
            weight: 8,
            name: "Emotional Manipulation",
            maxScore: 35,
            patterns: [
                /\bcongratulations\b/i,
                /\byou'?ve?\s*(?:won|been selected|been chosen)/i,
                /\bprize\b/i,
                /\blottery\b/i,
                /\binheritance\b/i,
                /\bprince\b/i,
                /\bnigerian?\b/i,
                /\bwealthy\b.*\brelative\b/i,
                /\bdied\s+in\s+(?:a\s+)?(?:car\s+)?accident\b/i,
                /\bcancer\b/i,
                /\bterminal(?:ly)?\s+ill\b/i,
                /\bstranded\b/i,
                /\bplease\s+(?:help|assist)\b/i,
                /\bi\s+am\s+(?:dying|sick|in\s+trouble)\b/i,
                /\binvestment\s+opportunity\b/i,
                /\bdouble\s+(?:your\s+)?money\b/i,
                /\bhigh\s+(?:yield|returns?)\b/i,
                /\bguarantee(?:ed)?\s+(?:profit|returns?|income)\b/i,
                /\bwork\s+from\s+home\b/i,
                /\bmake\s+money\s+(?:fast|quickly|online)\b/i,
                /\bearn\s+\$\d+/i,
                /\$\d+\s+(?:per\s+)?(?:hour|day|week)/i
            ]
        },

        grammar: {
            weight: 6,
            name: "Grammar & Spelling Issues",
            maxScore: 20,
            patterns: [
                /\bdear\s+(?:friend|customer|sir|madam|user|account\s+holder)\b(?![,.])/i,
                /\byou\s+have\s+been\s+select\b/i,  // "you have been select" (wrong tense)
                /\bkindly\s+(?:click|send|provide|verify|update)/i,
                /\byour\s+account\s+will\s+be\s+(?:block|suspend|close|delete)\b/i,  // Missing -ed
                /\bthis\s+is\s+(?:to\s+)?inform\s+you\b/i,
                /\bas\s+soon\s+as\s+possible\b/i,
                /\bdo\s+the\s+needful\b/i,
                /\bregard(?:s)?\b$/im,  // "regard" instead of "regards"
            ]
        },

        impersonation: {
            weight: 8,
            name: "Authority Impersonation",
            maxScore: 25,
            patterns: [
                /\bIRS\b/i,
                /\bFBI\b/i,
                /\bCIA\b/i,
                /\bDEA\b/i,
                /\bSocial\s+Security\s+Administration\b/i,
                /\bDepartment\s+of\s+(?:Treasury|Justice|Homeland)/i,
                /\bbank\s+(?:of\s+)?(?:America|America)?\b/i,
                /\bWells?\s+Fargo\b/i,
                /\bChase\s+Bank\b/i,
                /\bCitibank\b/i,
                /\bCapital\s+One\b/i,
                /\bInternal\s+Revenue\s+Service\b/i,
                /\bNorton\b/i,
                /\bMcAfee\b/i,
                /\bAvast\b/i,
                /\bAvira\b/i,
                /\bKaspersky\b/i,
                /\bBitdefender\b/i,
                /\bMalwarebytes\b/i,
                /\bWebroot\b/i,
                /\bESET\b/i,
                /\bTrend\s+Micro\b/i,
                /\bSophos\b/i
            ]
        }
    };

    // Grammar error detection patterns
    const grammarErrors = [
        { pattern: /\byou\s+have\s+been\s+select\b/i, error: "Wrong verb tense: 'you have been select' should be 'you have been selected'" },
        { pattern: /\bkindly\s+(?:click|send|provide|verify|update|reply)\b/i, error: "Unusual phrasing: 'kindly' is often used in scam emails" },
        { pattern: /\byour\s+account\s+will\s+be\s+(?:block|suspend|close|delete)\b/i, error: "Grammar error: missing past participle (blocked/suspended/closed/deleted)" },
        { pattern: /\bdo\s+the\s+needful\b/i, error: "Outdated/unnatural phrase commonly used in scams" },
    ];

    // Suspicious sender domain patterns (only triggers if NOT from legitimate domain)
    const suspiciousDomains = [
        { pattern: /[\w.-]*@(?!amazon\.com)[\w.-]*amazon[\w.-]*/i, name: "Spoofed Amazon domain" },
        { pattern: /[\w.-]*@(?!apple\.com)[\w.-]*apple[\w.-]*/i, name: "Spoofed Apple domain" },
        { pattern: /[\w.-]*@(?!paypal\.com)[\w.-]*paypal[\w.-]*/i, name: "Spoofed PayPal domain" },
        { pattern: /[\w.-]*@(?!microsoft\.com)[\w.-]*microsoft[\w.-]*/i, name: "Spoofed Microsoft domain" },
        { pattern: /[\w.-]*@(?!google\.com)[\w.-]*google[\w.-]*/i, name: "Spoofed Google domain" },
        { pattern: /[\w.-]*@(?!facebook\.com)[\w.-]*facebook[\w.-]*/i, name: "Spoofed Facebook domain" },
        { pattern: /[\w.-]*@(?!netflix\.com)[\w.-]*netflix[\w.-]*/i, name: "Spoofed Netflix domain" },
        { pattern: /[\w.-]*@(?!irs\.gov)[\w.-]*irs[\w.-]*/i, name: "Spoofed IRS domain" },
    ];

    // Sender email detection patterns (From: line analysis)
    const senderPatterns = {
        // Lookalike domains with character substitutions (0/O, 1/l, rn/m, etc.)
        lookalikeDomains: [
            /@(?:paypa[l1]|paypa[il]e|payp[a4][l1]|paypa)/i,  // paypal variants
            /@(?:amaz[0o]n|amaz[0o]ne?|amzn|amaz0ne)/i,  // amazon variants
            /@(?:app[l1]e|app[il]e|aplpe|app[e3]l)/i,  // apple variants
            /@(?:micros[0o]ft|micosoft|micr[0o]s[0o]ft|microsofts?upport)/i,  // microsoft variants
            /@(?:g[0o][0o]gle|goog[l1]e|g[o0]ogle|g00gle)/i,  // google variants
            /@(?:faceb[0o][0o]k|faceb[o0]ok|faceb[0o]k)/i,  // facebook variants
            /@(?:netf[l1]ix|netf[li]ix|netf[i1]ix)/i,  // netflix variants
            /@(?:bank[0o]famerica|bankofamer[i1]ca|b[0o]fa)/i,  // bank of america variants
            /@(?:we[l1]sfargo|w[e3]llsfargo|we[il]sfargo)/i,  // wells fargo variants
            /@(?:chase|chasebank)[^\w.-]/i,  // chase variants
        ],
        // Suspicious From: patterns
        fromLine: [
            /From:\s*[\w.-]*@(?!gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|icloud\.com|aol\.com|protonmail\.com)[\w.-]*\.(?:xyz|top|club|online|site|live|work|click|link|info|biz|name|tk|ml|ga|cf|gq|pw|ru|cn|br|in|co\.uk|co\.in|co\.nz)/i,  // Suspicious TLDs
            /From:\s*[\w.-]*@(?:support|admin|security|billing|service|help|info|noreply|no-reply)[\w.-]*\.(?!com|org|gov|edu|mil)/i,  // Generic sender on suspicious TLD
            /From:.*@.*\.(?:ga|ml|tk|gq|cf|pw|xyz|top|club|click|link|online|site|work)/i,  // Known spam TLDs
            /From:\s*[\w.-]*\d{5,}@(?:gmail|yahoo|outlook|hotmail)/i,  // Lots of numbers in personal email (suspicious)
        ],
        // Generic sender names that are red flags
        genericSender: [
            /From:\s*(?:support|admin|security|billing|customer service|help desk|notification|alert|warning)[^<]*@/i,
        ],
    };

    /**
     * Analyze sender information for suspicious patterns
     * @param {string} text - Email text
     * @returns {Object} - {isSuspicious: boolean, score: number, issues: array}
     */
    function analyzeSender(text) {
        const issues = [];
        let score = 0;
        
        // List of legitimate brand domains
        const legitimateDomains = ['amazon.com', 'apple.com', 'paypal.com', 'microsoft.com', 'google.com', 'facebook.com', 'netflix.com', 'irs.gov', 'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com', 'capitalone.com', 'norton.com', 'mcafee.com', 'avast.com', 'avira.com', 'kaspersky.com', 'bitdefender.com', 'malwarebytes.com', 'webroot.com', 'eset.com', 'trendmicro.com', 'sophos.com'];
        
        // Extract sender from From: line (also try without 'From:' prefix for plain emails)
        let fromMatch = text.match(/From:\s*([^\n<]+)?<?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?/i);
        
        // Also try to match bare email format: "Name <email>" or just "email"
        if (!fromMatch) {
            fromMatch = text.match(/([^\n<]+)?<?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?/i);
        }
        
        let isLegitimateDomain = false;
        
        if (fromMatch) {
            const senderEmail = fromMatch[2];
            const senderDomain = fromMatch[3].toLowerCase();
            const displayName = fromMatch[1] ? fromMatch[1].trim() : null;
            
            isLegitimateDomain = legitimateDomains.some(d => senderDomain === d || senderDomain.endsWith('.' + d));
            
            // Check for lookalike domains (skip if legitimate)
            if (!isLegitimateDomain) {
                for (const pattern of senderPatterns.lookalikeDomains) {
                    if (pattern.test(senderEmail)) {
                        issues.push({
                            match: senderEmail,
                            reason: `Lookalike domain detected: this email mimics a legitimate company`,
                            weight: 15
                        });
                        score += 15;
                    }
                }
            }
            
            // Check for suspicious TLDs in sender domain (skip if legitimate)
            if (!isLegitimateDomain) {
                const suspiciousTLDs = ['.xyz', '.top', '.club', '.online', '.site', '.live', '.work', '.click', '.link', '.info', '.biz', '.name', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.ru', '.cn', '.br'];
                for (const tld of suspiciousTLDs) {
                    if (senderDomain.endsWith(tld)) {
                        issues.push({
                            match: senderDomain,
                            reason: `Suspicious domain extension: ${tld} is commonly used in scams`,
                            weight: 10
                        });
                        score += 10;
                        break;
                    }
                }
            }
            
            // Check for generic sender names on non-corporate domains (skip if legitimate)
            if (displayName && !isLegitimateDomain) {
                const genericNames = ['support', 'admin', 'security', 'billing', 'customer service', 'help desk', 'notification', 'alert', 'warning'];
                for (const generic of genericNames) {
                    if (displayName.toLowerCase().includes(generic)) {
                        issues.push({
                            match: displayName,
                            reason: `Generic sender name "${displayName}" on unusual domain`,
                            weight: 8
                        });
                        score += 8;
                    }
                }
            }
            
            // Check for security software impersonation in display name
            if (displayName) {
                const securityBrands = ['norton', 'mcafee', 'avast', 'avira', 'kaspersky', 'bitdefender', 'malwarebytes', 'webroot', 'eset', 'trend micro', 'sophos'];
                for (const brand of securityBrands) {
                    if (displayName.toLowerCase().includes(brand)) {
                        // Check if domain is legitimate for this brand
                        const brandDomain = brand.replace(/\s+/g, '') + '.com';
                        if (!senderDomain.includes(brandDomain)) {
                            issues.push({
                                match: displayName,
                                reason: `Security software impersonation: "${brand}" in sender name but domain is not ${brandDomain}`,
                                weight: 18
                            });
                            score += 18;
                        }
                    }
                }
            }
            
            // Check for gibberish/random domain detection
            const domainParts = senderDomain.split('.')[0]; // Get main domain part (before TLD)
            if (domainParts && !isLegitimateDomain) {
                // Check if domain looks like random gibberish (10+ random chars)
                const randomCharPattern = /^[a-z]{10,}$/i;
                const hasRandomChars = randomCharPattern.test(domainParts);
                
                // Also check for high entropy (mix of random consonants/vowels)
                const vowelCount = (domainParts.match(/[aeiou]/gi) || []).length;
                const consonantCount = domainParts.length - vowelCount;
                const ratio = vowelCount / domainParts.length;
                
                // Gibberish domains typically have unusual vowel ratios and long random strings
                if ((hasRandomChars || (domainParts.length >= 10 && ratio > 0.2 && ratio < 0.5))) {
                    // Additional check: consecutive consonants (unusual in real words)
                    const consecutiveConsonants = domainParts.match(/[^aeiou]{4,}/gi);
                    if (consecutiveConsonants && consecutiveConsonants.length > 0) {
                        issues.push({
                            match: senderDomain,
                            reason: `Gibberish/random domain detected: "${domainParts}" appears to be randomly generated`,
                            weight: 15
                        });
                        score += 15;
                    }
                }
            }
        }
        
        // Check From: line patterns (only flag if domain is not legitimate)
        if (!isLegitimateDomain) {
            for (const pattern of senderPatterns.fromLine) {
                const match = text.match(pattern);
                if (match) {
                    issues.push({
                        match: match[0],
                        reason: `Suspicious From: line detected`,
                        weight: 12
                    });
                    score += 12;
                }
            }
            
            // Check generic sender patterns
            for (const pattern of senderPatterns.genericSender) {
                const match = text.match(pattern);
                if (match) {
                    issues.push({
                        match: match[0],
                        reason: `Generic sender name often used in scams`,
                        weight: 8
                    });
                    score += 8;
                }
            }
        }
        
        return {
            isSuspicious: issues.length > 0,
            score: Math.min(score, 40),
            issues: issues
        };
    }

    /**
     * Strip HTML tags from text while preserving content
     * @param {string} text - Text that may contain HTML
     * @returns {string} - Plain text
     */
    function stripHtml(text) {
        if (!text) return text;
        // Create a temporary element to parse HTML (browser environment)
        if (typeof document !== 'undefined') {
            const temp = document.createElement('div');
            temp.innerHTML = text;
            return temp.textContent || temp.innerText || text;
        }
        // Fallback regex-based stripping for non-browser environments
        return text
            .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')  // Remove style blocks
            .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')  // Remove script blocks
            .replace(/<[^>]+>/g, ' ')  // Replace tags with space
            .replace(/&nbsp;/g, ' ')  // Decode common entities
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/\s+/g, ' ')  // Normalize whitespace
            .trim();
    }

    /**
     * Analyze email text for scam indicators
     * @param {string} emailText - The email text to analyze
     * @returns {Object} Analysis results
     */
    function analyze(emailText) {
        if (!emailText || typeof emailText !== 'string') {
            return {
                riskLevel: 'UNKNOWN',
                score: 0,
                redFlags: [],
                matchedPatterns: {},
                disclaimer: "⚠️ This tool provides guidance, not guarantees. Scammers evolve constantly. When in doubt, contact the organization directly using official contact information. This is not financial or legal advice."
            };
        }

        // Limit text length to prevent hanging
        // First strip any HTML tags (users may paste HTML from email clients)
        const text = stripHtml(emailText).trim().slice(0, 10000);
        const results = {
            riskLevel: 'LOW',
            score: 0,
            redFlags: [],
            matchedPatterns: {},
            disclaimer: "⚠️ This tool provides guidance, not guarantees. Scammers evolve constantly. When in doubt, contact the organization directly using official contact information. This is not financial or legal advice."
        };

        let totalScore = 0;
        const maxScore = 100;

        // Check each pattern category
        for (const [category, config] of Object.entries(patterns)) {
            const matches = [];
            let categoryScore = 0;
            const maxCategoryScore = config.maxScore || 50;

            for (const pattern of config.patterns) {
                const found = text.match(pattern);
                if (found) {
                    matches.push({
                        pattern: pattern.toString(),
                        match: found[0],
                        context: getContext(text, found.index, found[0].length)
                    });
                }
            }

            // Score per match, capped at maxCategoryScore
            if (matches.length > 0) {
                categoryScore = Math.min(matches.length * config.weight, maxCategoryScore);
                totalScore += categoryScore;
                
                results.matchedPatterns[category] = {
                    name: config.name,
                    weight: config.weight,
                    score: categoryScore,
                    matches: matches.map(m => m.match)
                };

                results.redFlags.push({
                    category: config.name,
                    weight: config.weight,
                    score: categoryScore,
                    matches: matches
                });
            }
        }

        // Check for suspicious sender patterns (From: line analysis)
        const senderInfo = analyzeSender(text);
        if (senderInfo.isSuspicious) {
            totalScore += senderInfo.score;
            for (const issue of senderInfo.issues) {
                results.redFlags.push({
                    category: "Suspicious Sender",
                    weight: issue.weight,
                    matches: [{ match: issue.match, context: issue.reason }]
                });
            }
        }

        // Check for suspicious domains (legacy patterns)
        for (const domain of suspiciousDomains) {
            if (domain.pattern.test(text)) {
                totalScore += 15;
                const match = text.match(domain.pattern);
                results.redFlags.push({
                    category: "Suspicious Sender",
                    weight: 15,
                    matches: [{ match: match[0], context: domain.name }]
                });
            }
        }

        // Check grammar issues
        for (const error of grammarErrors) {
            if (error.pattern.test(text)) {
                totalScore += 5;
                const match = text.match(error.pattern);
                results.redFlags.push({
                    category: "Grammar Issue",
                    weight: 5,
                    matches: [{ match: match[0], context: error.error }]
                });
            }
        }

        // Calculate final score (cap at 100)
        results.score = Math.min(totalScore, maxScore);

        // Determine risk level - adjusted thresholds for better detection
        if (results.score >= 40) {
            results.riskLevel = 'HIGH';
        } else if (results.score >= 20) {
            results.riskLevel = 'MEDIUM';
        } else if (results.score >= 10) {
            results.riskLevel = 'LOW';
        } else {
            results.riskLevel = 'UNABLE TO DETERMINE';
        }

        return results;
    }

    /**
     * Get context around a matched pattern
     */
    function getContext(text, index, length, contextSize = 30) {
        const start = Math.max(0, index - contextSize);
        const end = Math.min(text.length, index + length + contextSize);
        let context = text.slice(start, end);
        
        if (start > 0) context = '...' + context;
        if (end < text.length) context = context + '...';
        
        return context;
    }

    // Public API
    return {
        analyze: analyze,
        patterns: patterns,
        version: '1.0.0'
    };
})();

// Export for Node.js if available
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ScamDetector;
}