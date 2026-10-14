/**
 * ScamShield AI — Threat Detection & Heuristic Engine
 * Version 2.4 (Client-Side Privacy Edition)
 */

(() => {
    'use strict';

    // =========================================================================
    // 1. SOUND SYNTHESIS ENGINE (Web Audio API - Zero External Dependencies)
    // =========================================================================
    let audioCtx = null;
    let soundEnabled = true;

    // Load sound preference from localStorage
    try {
        const savedSound = localStorage.getItem('scamshield_sound');
        if (savedSound !== null) soundEnabled = savedSound === 'true';
    } catch (_) {}

    function getAudioContext() {
        if (!audioCtx) {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (AudioContextClass) audioCtx = new AudioContextClass();
        }
        if (audioCtx && audioCtx.state === 'suspended') {
            audioCtx.resume();
        }
        return audioCtx;
    }

    function playSound(type) {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;

            if (type === 'click') {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(800, now);
                osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
                gain.gain.setValueAtTime(0.08, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start(now);
                osc.stop(now + 0.05);
            } else if (type === 'scan') {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(320, now);
                osc.frequency.linearRampToValueAtTime(900, now + 0.2);
                gain.gain.setValueAtTime(0.04, now);
                gain.gain.linearRampToValueAtTime(0.001, now + 0.2);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start(now);
                osc.stop(now + 0.2);
            } else if (type === 'alert-danger') {
                const osc1 = ctx.createOscillator();
                const osc2 = ctx.createOscillator();
                const gain = ctx.createGain();
                osc1.type = 'sawtooth';
                osc2.type = 'sawtooth';
                osc1.frequency.setValueAtTime(440, now);
                osc2.frequency.setValueAtTime(448, now);
                gain.gain.setValueAtTime(0.07, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
                osc1.connect(gain);
                osc2.connect(gain);
                gain.connect(ctx.destination);
                osc1.start(now);
                osc2.start(now);
                osc1.stop(now + 0.4);
                osc2.stop(now + 0.4);
            } else if (type === 'success') {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(523.25, now); // C5
                osc.frequency.setValueAtTime(659.25, now + 0.08); // E5
                osc.frequency.setValueAtTime(783.99, now + 0.16); // G5
                gain.gain.setValueAtTime(0.08, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start(now);
                osc.stop(now + 0.35);
            }
        } catch (_) {}
    }

    // =========================================================================
    // 2. HEURISTIC THREAT DICTIONARY & REGEX RULES
    // =========================================================================
    const THREAT_RULES = [
        // 1. Psychological Urgency & Deadlines
        {
            id: 'urgency_coercion',
            category: 'Psychological Manipulation',
            severity: 'critical',
            weight: 22,
            pattern: /\b(urgently?|immediately|right now|within 24 hours|within 2 hours|limited time|deadline expires|last warning|final notice|act fast|time is running out)\b/i,
            title: 'Urgency & Artificial Scarcity',
            desc: 'The sender uses pressurized deadlines to panic you into acting before verifying.'
        },
        // 2. Sensitive Credentials & Authentication Theft
        {
            id: 'credential_harvesting',
            category: 'Credential Harvesting',
            severity: 'critical',
            weight: 30,
            pattern: /\b(one-?time password|otp|verification code|security pin|atm pin|cvv|netbanking password|passcode|debit card pin|login credentials)\b/i,
            title: 'Credential / OTP Phishing',
            desc: 'Legitimate financial and service organizations will NEVER ask for your OTP, PIN, or password.'
        },
        // 3. Bank Account Block / Suspension Threats
        {
            id: 'account_freeze_threat',
            category: 'Impersonation & Coercion',
            severity: 'critical',
            weight: 26,
            pattern: /\b(account (has been )?suspended|account (has been )?blocked|funds will be frozen|card deactivated|kyc (is )?pending|update your pan card|aadhaar link required|sim will be blocked)\b/i,
            title: 'Fake Account Suspension / KYC Coercion',
            desc: 'Fraudsters impersonate banks claiming accounts are locked to trick victims into entering credentials on fake portals.'
        },
        // 4. Digital Arrest / Law Enforcement Extortion
        {
            id: 'digital_arrest_extortion',
            category: 'Authority Extortion',
            severity: 'critical',
            weight: 35,
            pattern: /\b(digital arrest|cbi|interpol|customs department|narcotics|police warrant|court summons|arrest warrant|illegal parcel|money laundering case|seized package)\b/i,
            title: 'Digital Arrest / Police Extortion',
            desc: 'Extremely dangerous scam: Impersonating police/customs claiming you are under video investigation.'
        },
        // 5. Utility / Electricity Cutoff Threats
        {
            id: 'utility_disconnection',
            category: 'Utility Scam',
            severity: 'critical',
            weight: 24,
            pattern: /\b(electricity will be disconnected|power will be cut|bill unpaid|officer contact|call immediately at [0-9+]+)\b/i,
            title: 'Urgent Utility Disconnection Scam',
            desc: 'Claims your electricity will be disconnected tonight. Power boards never send personal phone numbers for bill settlement.'
        },
        // 6. Advance Fee & Payment Redirection
        {
            id: 'advance_fee_trap',
            category: 'Financial Trap',
            severity: 'high',
            weight: 20,
            pattern: /\b(processing fee|customs duty fee|clearance fee|transfer fee|advance deposit|activation fee|unfreeze fee)\b/i,
            title: 'Advance Fee Demand',
            desc: 'Demanding upfront money to release a prize, package, or job payment is the hallmark of advance-fee fraud.'
        },
        // 7. Non-traceable Payment Requests (Gift Cards, Crypto, Telegram)
        {
            id: 'untraceable_payment',
            category: 'Financial Trap',
            severity: 'high',
            weight: 22,
            pattern: /\b(gift cards?|itunes card|google play card|steam card|usdt|bitcoin|send eth|crypto wallet|telegram admin|t\.me\/)\b/i,
            title: 'Untraceable Payment Method',
            desc: 'Demands payment via gift cards or crypto wallets that cannot be reversed or traced once sent.'
        },
        // 8. Unrealistic Wealth / Lottery / Crypto Doubler
        {
            id: 'unrealistic_wealth',
            category: 'Greed Trap',
            severity: 'high',
            weight: 22,
            pattern: /\b(won (a )?lottery|cash prize winner|lucky draw|claim \$[0-9,]+|guaranteed 100% return|double your crypto|earn \$[0-9]+ daily|part-time job liking videos)\b/i,
            title: 'Unsolicited Prize or Guaranteed Profit',
            desc: 'Promise of unearned wealth, fake investment multipliers, or high-paying easy remote jobs.'
        },
        // 9. Malicious / APK File Download Prompt
        {
            id: 'apk_malware_prompt',
            category: 'Malware Risk',
            severity: 'critical',
            weight: 28,
            pattern: /\b(\.apk|download app to verify|install this application|anydesk|teamviewer|rustdesk|quicksupport)\b/i,
            title: 'Dangerous Remote Access / APK Download',
            desc: 'Prompts you to install an Android APK or remote desk viewer that allows scammers to view and control your phone.'
        },
        // 10. Failed Package / Smishing Redelivery
        {
            id: 'parcel_smishing',
            category: 'Phishing',
            severity: 'high',
            weight: 20,
            pattern: /\b(package (cannot be|could not be) delivered|missing street number|reschedule delivery|postal update|update your address)\b/i,
            title: 'Package Delivery Smishing',
            desc: 'Pretends to be a delivery carrier (USPS, FedEx, DHL, India Post) to collect card details under the guise of a small redelivery fee.'
        },
        // 11. Generic Shortened or Suspicious Web Links
        {
            id: 'suspicious_link',
            category: 'Phishing Link',
            severity: 'high',
            weight: 18,
            pattern: /https?:\/\/[^\s]+/i,
            title: 'External Web Link Detected',
            desc: 'Contains a direct hyperlink. Always verify the domain hostname before clicking or entering passwords.'
        },
        // 12. Deceptive Call-to-Action phrases
        {
            id: 'deceptive_cta',
            category: 'Call to Action',
            severity: 'warning',
            weight: 12,
            pattern: /\b(click here|tap the link|update here|verify now|claim your reward|open this link)\b/i,
            title: 'Coercive Click Trigger',
            desc: 'Direct instruction directing you toward an external phishing destination.'
        }
    ];

    // Known dangerous or disposable TLDs frequently abused by phishing kits
    const SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.icu', '.cam', '.work', '.click', '.monster', '.rest', '.sbs', '.cfd'];

    // High profile brands commonly spoofed
    const SPOOFED_BRANDS = [
        'paypal', 'amazon', 'apple', 'netflix', 'microsoft', 'google', 'chase', 'wellsfargo', 
        'bankofamerica', 'hdfc', 'sbi', 'icici', 'fedex', 'dhl', 'usps', 'ups', 'whatsapp', 'telegram'
    ];

    // =========================================================================
    // 3. PRESET SCAM SCENARIOS
    // =========================================================================
    const PRESETS = {
        bank: "Dear SBI customer, your NetBanking account has been suspended due to pending KYC verification. Click immediately here to update PAN card: http://sbi-secure-kyc.update-portal.xyz/verify or your account will be permanently blocked in 2 hours.",
        delivery: "FedEx Notice: Your delivery package #FX-93820 has been put on hold due to incorrect street number. Reschedule your parcel now and confirm re-delivery fee of $1.50 here: https://fedx-parcel-support.top/delivery-confirm",
        crypto: "Official Binance Giveaway: CEO is giving back to the community! Send 0.5 ETH to our smart contract address and receive 1.0 ETH back immediately! Limited to first 50 participants: https://binance-event-doubler.cam",
        job: "Hello! We are currently hiring Remote Assistants for Google Review Marketing. Work only 30 minutes/day liking YouTube videos, earn $300-$700 daily. To claim your first payout, transfer $40 registration fee to Telegram Admin @earnfast_manager.",
        arrest: "URGENT NOTICE: CBI and Crime Branch Mumbai have seized an illegal parcel containing narcotics and fake passports registered under your Aadhaar. Digital arrest warrant issued. Contact Customs Investigator immediately on WhatsApp or face immediate arrest.",
        legit: "Your Amazon order #114-8392019-382910 has shipped and will arrive tomorrow by 8 PM. You can track your shipment anytime in your official Amazon app or at https://www.amazon.com/your-orders."
    };

    // =========================================================================
    // 4. INSTINCT QUIZ DATA
    // =========================================================================
    const QUIZ_QUESTIONS = [
        {
            sender: "HDFC Alert",
            message: "Dear customer, your card is blocked due to unusual activity. To reactivate immediately without branch visit, click: http://hdfcbank-portal.online/unblock",
            isScam: true,
            explanation: "🚨 SCAM! Notice the unofficial domain 'hdfcbank-portal.online'. Banks never use generic .online or third-party web addresses, nor do they request unblocking via random SMS links."
        },
        {
            sender: "Netflix",
            message: "Your monthly Netflix membership has been renewed successfully for $15.49. You can view your invoice anytime inside your account settings at https://www.netflix.com/youraccount.",
            isScam: false,
            explanation: "🛡️ LEGITIMATE! The link points directly to the genuine, official 'netflix.com' domain with HTTPS. It is purely informational and doesn't demand urgent PINs or emergency money."
        },
        {
            sender: "WhatsApp +62 831-92...",
            message: "Hi! I am Emma from Global Talent HR. Your profile has been selected for remote product review. Earn $500/day. Send $30 processing fee via USDT to join our training Telegram group.",
            isScam: true,
            explanation: "🚨 SCAM! Classic task-based advance-fee fraud. Legitimate employers NEVER ask applicants to pay registration fees or transfer cryptocurrency to start working."
        },
        {
            sender: "USPS Tracking",
            message: "USPS: Package 9400111202555353139314 is scheduled for delivery today. Sign up for delivery alerts or manage package options at https://tools.usps.com/go/TrackConfirmAction.",
            isScam: false,
            explanation: "🛡️ LEGITIMATE! Uses the official government 'usps.com' domain without fake fees or panic-inducing threats."
        },
        {
            sender: "Police / Customs Dept",
            message: "This is Cyber Cell Delhi. A FedEx package in your name containing expired medications and credit cards was impounded. You are placed under Digital Arrest. Open Skype link to depose before magistrate.",
            isScam: true,
            explanation: "🚨 SCAM! 'Digital Arrest' is a complete fabrication used by international extortion syndicates. No law enforcement agency or court conducts trials or arrests via Skype or WhatsApp."
        }
    ];

    // =========================================================================
    // 5. ENGINE CORE: SCANNING & ANALYSIS
    // =========================================================================

    /**
     * Deep inspects a URL for deceptive patterns
     */
    function inspectUrl(rawUrl) {
        const urlFindings = [];
        let urlRisk = 0;

        let parsed;
        try {
            // Add scheme if missing
            let normalized = rawUrl.trim();
            if (!/^https?:\/\//i.test(normalized)) {
                normalized = 'https://' + normalized;
            }
            parsed = new URL(normalized);
        } catch (_) {
            return {
                valid: false,
                risk: 15,
                findings: [{
                    title: 'Malformed URL',
                    desc: 'The link string is improperly formatted or obfuscated.',
                    severity: 'warning'
                }]
            };
        }

        const hostname = parsed.hostname.toLowerCase();
        const protocol = parsed.protocol;

        // Check 1: Insecure HTTP
        if (protocol === 'http:') {
            urlRisk += 15;
            urlFindings.push({
                title: 'Insecure Connection (HTTP)',
                desc: 'Traffic is transmitted without encryption. Modern authentic banks and retailers mandate HTTPS.',
                severity: 'warning'
            });
        }

        // Check 2: IP address used instead of domain name
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            urlRisk += 35;
            urlFindings.push({
                title: 'Direct IP Address Host',
                desc: `The address (${hostname}) points directly to a raw server IP rather than an authorized branded domain name.`,
                severity: 'critical'
            });
        }

        // Check 3: Suspicious Phishing TLDs
        for (const tld of SUSPICIOUS_TLDS) {
            if (hostname.endsWith(tld)) {
                urlRisk += 25;
                urlFindings.push({
                    title: `High-Risk TLD (${tld})`,
                    desc: `The top-level domain ${tld} is heavily favored by ephemeral phishing campaigns due to cheap registration.`,
                    severity: 'critical'
                });
                break;
            }
        }

        // Check 4: Brand Spoofing / Typosquatting in Subdomains or Lookalikes
        for (const brand of SPOOFED_BRANDS) {
            if (hostname.includes(brand)) {
                // Check if it's the actual genuine domain or a fake combination
                const isReal = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
                if (!isReal) {
                    urlRisk += 35;
                    urlFindings.push({
                        title: `Brand Impersonation (${brand.toUpperCase()})`,
                        desc: `The domain references '${brand}' but resolves to an unauthorized host (${hostname}).`,
                        severity: 'critical'
                    });
                }
            }
        }

        // Check 5: Excessive Subdomain nesting (e.g. login.sbi.com.user-auth.xyz)
        const parts = hostname.split('.');
        if (parts.length > 3) {
            urlRisk += 15;
            urlFindings.push({
                title: 'Deceptive Multi-Level Subdomains',
                desc: 'Attackers create subdomains resembling legitimate companies to deceive mobile screens.',
                severity: 'warning'
            });
        }

        return {
            valid: true,
            hostname,
            risk: urlRisk,
            findings: urlFindings
        };
    }

    /**
     * Inspects a phone number or sender header
     */
    function inspectPhone(input) {
        const text = input.trim();
        const findings = [];
        let risk = 0;

        // Check spoofed alphanumeric header format (e.g., standard Indian headers have 2 alpha chars + 6 digits/chars)
        if (/^[a-zA-Z]{2}-[a-zA-Z0-9]{6,}$/.test(text)) {
            findings.push({
                title: 'Enterprise SMS Header Detected',
                desc: 'Header matches telecommunication business sender format, but beware: headers can sometimes be spoofed through overseas SMS gateways.',
                severity: 'notice'
            });
            risk += 10;
        }

        // Check international unusual codes
        if (/^\+(234|880|92|254|233|229)/.test(text)) {
            risk += 25;
            findings.push({
                title: 'High-Incidence International Origin',
                desc: `The phone number prefix (${text.slice(0, 4)}) originates from a region with elevated reports of cross-border telecom fraud syndicates.`,
                severity: 'warning'
            });
        }

        // Check toll-free spoofing (+1 800 / 888 / 877)
        if (/^\+?1\s*\(?(800|888|877|866|855)\)?/i.test(text)) {
            risk += 15;
            findings.push({
                title: 'Toll-Free Number Marker',
                desc: 'Toll-free numbers are frequently spoofed by tech support and fake bank refund call centers.',
                severity: 'warning'
            });
        }

        return {
            risk,
            findings
        };
    }

    /**
     * Core heuristic analysis execution
     */
    function analyzeText(rawText) {
        const text = rawText.trim();
        if (!text) return null;

        let totalScore = 0;
        const triggeredRules = [];
        const detectedKeywords = [];

        // 1. Evaluate Text Against Rulebook
        THREAT_RULES.forEach(rule => {
            const match = text.match(rule.pattern);
            if (match) {
                totalScore += rule.weight;
                triggeredRules.push(rule);
                detectedKeywords.push({
                    word: match[0],
                    severity: rule.severity,
                    title: rule.title
                });
            }
        });

        // 2. Extract and inspect all embedded URLs
        const urlRegex = /https?:\/\/[^\s]+/gi;
        const foundUrls = text.match(urlRegex) || [];
        const urlAnalyses = [];

        foundUrls.forEach(url => {
            const result = inspectUrl(url);
            urlAnalyses.push({ url, result });
            totalScore += result.risk;
            result.findings.forEach(f => {
                triggeredRules.push({
                    id: 'url_' + Math.random().toString(36).substring(7),
                    category: 'Domain & Link Intelligence',
                    severity: f.severity,
                    title: f.title,
                    desc: f.desc
                });
            });
        });

        // 3. Multiplier for Toxic Combinations (Social Engineering compound risk)
        const hasUrgency = triggeredRules.some(r => r.id === 'urgency_coercion' || r.id === 'account_freeze_threat');
        const hasCredentials = triggeredRules.some(r => r.id === 'credential_harvesting');
        const hasLink = foundUrls.length > 0;
        const hasPayment = triggeredRules.some(r => r.id === 'advance_fee_trap' || r.id === 'untraceable_payment');

        if (hasUrgency && hasCredentials) {
            totalScore += 20; // Deadly combo: Fear + Credential harvesting
        }
        if (hasUrgency && hasLink) {
            totalScore += 15; // Urgency driving victim to a link
        }
        if (hasPayment && hasLink) {
            totalScore += 15; // Financial trap + link
        }

        // Clamp score between 0 and 100
        const finalScore = Math.min(Math.max(Math.round(totalScore), 0), 100);

        // Calculate confidence
        let confidence = 88;
        if (text.length > 50) confidence += 4;
        if (triggeredRules.length >= 2) confidence += 4;
        confidence = Math.min(confidence, 98);

        // Determine Level, Color, Badges
        let threatLevel = '';
        let badgeClass = '';
        let color = '';
        let headline = '';
        let description = '';

        if (finalScore >= 70) {
            threatLevel = 'Critical Scam Hazard';
            badgeClass = 'badge-critical';
            color = '#ef4444';
            headline = '🛑 High-Probability Cyber Fraud Attempt';
            description = 'Multiple severe attack signatures detected. Strong indicators of social engineering, credential harvesting, or extortion tactics.';
        } else if (finalScore >= 40) {
            threatLevel = 'Moderate Threat / Caution';
            badgeClass = 'badge-warning';
            color = '#f59e0b';
            headline = '⚠️ Suspicious Red Flags Detected';
            description = 'This communication exhibits deceptive phrasing or unverified destinations. Exercise extreme caution before engaging.';
        } else if (finalScore >= 16) {
            threatLevel = 'Low Risk / Cautionary';
            badgeClass = 'badge-notice';
            color = '#38bdf8';
            headline = '🔍 Few Warning Markers Identified';
            description = 'Some keywords or external links warrant careful inspection, but no critical phishing signatures were triggered.';
        } else {
            threatLevel = 'Clean / Minimal Risk';
            badgeClass = 'badge-notice';
            color = '#10b981';
            headline = '🛡️ No Major Scam Indicators';
            description = 'No obvious manipulative urgency or known fraud patterns detected. Always verify unexpected payment requests independently.';
        }

        // Determine Attacker Blueprint
        let blueprint = '';
        if (triggeredRules.some(r => r.id === 'digital_arrest_extortion')) {
            blueprint = 'Extortion & Coercion: The attacker is manufacturing a fabricated legal emergency to panic the victim into transferring "bond" or "bail" funds to a personal account.';
        } else if (hasCredentials || (hasUrgency && hasLink)) {
            blueprint = 'Credential & Account Takeover Phishing: The attacker directs you to a counterfeit landing page designed to mimic your bank or service provider to harvest login passwords and OTPs.';
        } else if (hasPayment || triggeredRules.some(r => r.id === 'unrealistic_wealth')) {
            blueprint = 'Advance-Fee / Investment Trap: The attacker leverages greed or fear to persuade you to send upfront deposits or crypto which will never be returned.';
        } else if (triggeredRules.some(r => r.id === 'parcel_smishing')) {
            blueprint = 'Smishing Credit Card Harvest: Under the pretext of a $1 redelivery fee, the link captures your complete credit card number, CVV, and billing details.';
        } else {
            blueprint = 'General Suspicious Contact: The sender seeks engagement or link clicks. Treat unverified incoming messages with healthy skepticism.';
        }

        // Safety Protocol
        const protocols = [];
        if (finalScore >= 40) {
            protocols.push('Do NOT click any links, download attachments, or open APK files in this message.');
            protocols.push('Never disclose OTPs, PINs, or NetBanking passwords under any circumstances.');
            protocols.push('If this claims to be your bank or delivery service, navigate manually to their official app or website.');
            protocols.push('Block and report this sender number/email to your carrier and cyber authorities.');
        } else {
            protocols.push('Verify the sender identity directly through previously trusted contact information.');
            protocols.push('Check the exact domain spelling in any link before submitting login details.');
            protocols.push('Keep two-factor authentication (2FA) enabled on all vital financial and personal accounts.');
        }

        return {
            score: finalScore,
            level: threatLevel,
            badgeClass,
            color,
            headline,
            description,
            confidence,
            flags: triggeredRules,
            keywords: detectedKeywords,
            urlAnalyses,
            blueprint,
            protocols,
            originalText: text
        };
    }

    // =========================================================================
    // 6. UI RENDERER & INTERACTIVE HIGHLIGHTER
    // =========================================================================

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Builds highlighted HTML of the user's text highlighting suspicious matches
     */
    function renderHighlightedText(text, keywords) {
        if (!keywords || keywords.length === 0) {
            return `<p>${escapeHtml(text)}</p>`;
        }

        let html = escapeHtml(text);

        // Sort keywords by length descending so longer phrases match first
        const sorted = [...keywords].sort((a, b) => b.word.length - a.word.length);

        sorted.forEach(k => {
            const escapedWord = escapeHtml(k.word);
            const regex = new RegExp(`(${escapedWord.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
            const markClass = k.severity === 'critical' ? 'hl-danger' : (k.severity === 'high' ? 'hl-warning' : 'hl-info');
            html = html.replace(regex, `<mark class="${markClass}" title="${escapeHtml(k.title)}">$1</mark>`);
        });

        return `<p>${html}</p>`;
    }

    /**
     * Animates the circular gauge
     */
    function animateGauge(targetScore, color) {
        const gaugeCircle = document.getElementById('gaugeCircle');
        const gaugeScoreElem = document.getElementById('gaugeScore');
        if (!gaugeCircle || !gaugeScoreElem) return;

        // Circumference for r=50 is 2 * PI * 50 ≈ 314.159
        const circumference = 314;
        const offset = circumference - (targetScore / 100) * circumference;

        gaugeCircle.style.stroke = color;
        gaugeCircle.style.strokeDasharray = circumference;
        gaugeCircle.style.strokeDashoffset = offset;

        // Number counter animation
        let current = 0;
        const step = Math.ceil(targetScore / 25) || 1;
        const interval = setInterval(() => {
            current += step;
            if (current >= targetScore) {
                current = targetScore;
                clearInterval(interval);
            }
            gaugeScoreElem.textContent = current;
        }, 20);
    }

    /**
     * Renders complete assessment into the DOM
     */
    function displayAssessment(result) {
        const resultSection = document.getElementById('assessmentResult');
        const threatBadge = document.getElementById('threatBadge');
        const threatHeadline = document.getElementById('threatHeadline');
        const threatDesc = document.getElementById('threatDescription');
        const confidenceVal = document.getElementById('confidenceVal');
        const flagCount = document.getElementById('flagCount');
        const highlightedContent = document.getElementById('highlightedContent');
        const flagsGrid = document.getElementById('flagsGrid');
        const blueprintText = document.getElementById('blueprintText');
        const protocolList = document.getElementById('protocolList');

        if (!resultSection) return;

        // Banner values
        threatBadge.textContent = result.level;
        threatBadge.className = `threat-level-badge ${result.badgeClass}`;
        threatHeadline.textContent = result.headline;
        threatDesc.textContent = result.description;
        confidenceVal.textContent = `${result.confidence}%`;
        flagCount.textContent = result.flags.length;

        // Animate circular gauge
        animateGauge(result.score, result.color);

        // Highlighted text
        highlightedContent.innerHTML = renderHighlightedText(result.originalText, result.keywords);

        // Flags Grid
        if (result.flags.length > 0) {
            flagsGrid.innerHTML = result.flags.map(f => {
                const badge = f.severity === 'critical' ? 'badge-critical' : (f.severity === 'high' ? 'badge-warning' : 'badge-notice');
                return `
                    <div class="flag-card">
                        <div class="flag-header">
                            <span class="flag-name">${escapeHtml(f.title)}</span>
                            <span class="flag-badge ${badge}">${escapeHtml(f.severity)}</span>
                        </div>
                        <p class="flag-desc">${escapeHtml(f.desc)}</p>
                    </div>
                `;
            }).join('');
        } else {
            flagsGrid.innerHTML = `
                <div class="flag-card" style="grid-column: 1 / -1;">
                    <div class="flag-header">
                        <span class="flag-name">No Critical Red Flags</span>
                        <span class="flag-badge badge-notice">Clear</span>
                    </div>
                    <p class="flag-desc">Our heuristic engine evaluated the content against known deceptive patterns and identified no immediate threats.</p>
                </div>
            `;
        }

        // Blueprint
        blueprintText.textContent = result.blueprint;

        // Protocol
        protocolList.innerHTML = result.protocols.map(p => `<li>${escapeHtml(p)}</li>`).join('');

        // Make visible
        resultSection.classList.remove('hidden');
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        // Audio cue
        if (result.score >= 50) {
            playSound('alert-danger');
        } else {
            playSound('success');
        }
    }

    // =========================================================================
    // 7. TOAST NOTIFICATION UTILITY
    // =========================================================================
    function showToast(message, icon = '🛡️') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 3200);
    }

    // =========================================================================
    // 8. SCAN HISTORY MANAGER (localStorage)
    // =========================================================================
    const HISTORY_KEY = 'scamshield_history_v1';

    function getHistory() {
        try {
            return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
        } catch (_) {
            return [];
        }
    }

    function saveToHistory(result) {
        const history = getHistory();
        const item = {
            id: Date.now(),
            score: result.score,
            level: result.level,
            badgeClass: result.badgeClass,
            snippet: result.originalText.slice(0, 100),
            fullText: result.originalText,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })
        };

        // Prepend and cap at 15 items
        history.unshift(item);
        if (history.length > 15) history.pop();

        try {
            localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        } catch (_) {}

        updateHistoryUI();
        showToast('Saved to scan history', '💾');
    }

    function updateHistoryUI() {
        const history = getHistory();
        const historyList = document.getElementById('historyList');
        const emptyMsg = document.getElementById('emptyHistoryMsg');
        const badge = document.getElementById('historyBadge');

        if (badge) badge.textContent = history.length;
        if (!historyList) return;

        if (history.length === 0) {
            historyList.innerHTML = `
                <div class="empty-history" id="emptyHistoryMsg">
                    <p>No recent scans recorded yet. Analyze a message above to see your history log.</p>
                </div>
            `;
            return;
        }

        historyList.innerHTML = history.map(item => `
            <div class="history-item" data-id="${item.id}" title="Click to re-inspect">
                <div class="hist-left">
                    <span class="hist-badge ${item.badgeClass}">${item.score}/100</span>
                    <div class="hist-details">
                        <div class="hist-snippet">${escapeHtml(item.snippet)}...</div>
                        <div class="hist-meta">${escapeHtml(item.level)} • ${escapeHtml(item.timestamp)}</div>
                    </div>
                </div>
                <button type="button" class="btn-text" data-action="load" data-id="${item.id}">View ↗</button>
            </div>
        `).join('');

        // Attach click listeners to reload history items
        historyList.querySelectorAll('.history-item').forEach(el => {
            el.addEventListener('click', () => {
                const id = parseInt(el.dataset.id, 10);
                const record = history.find(h => h.id === id);
                if (record) {
                    const messageInput = document.getElementById('messageInput');
                    if (messageInput) {
                        messageInput.value = record.fullText;
                        updateCharCount();
                    }
                    // Switch to message tab
                    switchTab('messageTab');
                    // Run analysis
                    executeScan();
                }
            });
        });
    }

    function clearHistory() {
        try {
            localStorage.removeItem(HISTORY_KEY);
        } catch (_) {}
        updateHistoryUI();
        showToast('Scan history cleared', '🗑️');
    }

    // =========================================================================
    // 9. SCAN EXECUTION CONTROLLER & PROGRESS SIMULATION
    // =========================================================================
    let currentAnalysisResult = null;

    function executeScan() {
        playSound('scan');

        // Determine active tab
        const activeTab = document.querySelector('.tab-content.active');
        let textToAnalyze = '';

        if (activeTab && activeTab.id === 'urlTab') {
            const urlInput = document.getElementById('urlInput');
            textToAnalyze = urlInput ? urlInput.value.trim() : '';
            if (!textToAnalyze) {
                showToast('Please enter a website link to inspect.', '⚠️');
                return;
            }
        } else if (activeTab && activeTab.id === 'phoneTab') {
            const phoneInput = document.getElementById('phoneInput');
            textToAnalyze = phoneInput ? phoneInput.value.trim() : '';
            if (!textToAnalyze) {
                showToast('Please enter a phone number or sender header.', '⚠️');
                return;
            }
        } else {
            const messageInput = document.getElementById('messageInput');
            textToAnalyze = messageInput ? messageInput.value.trim() : '';
            if (!textToAnalyze) {
                showToast('Please paste a message or text to analyze.', '⚠️');
                return;
            }
        }

        // High-tech scanning simulation
        const progressBox = document.getElementById('scanProgressBox');
        const progressBar = document.getElementById('scanProgressBar');
        const stepText = document.getElementById('scanStepText');
        const resultSection = document.getElementById('assessmentResult');

        if (resultSection) resultSection.classList.add('hidden');
        if (progressBox) progressBox.classList.remove('hidden');

        const steps = [
            { text: 'Extracting linguistic markers & sentiment pressure...', pct: 25 },
            { text: 'Auditing domain spoofing & deceptive URL schemes...', pct: 55 },
            { text: 'Cross-referencing social engineering threat catalog...', pct: 85 },
            { text: 'Synthesizing proactive threat score...', pct: 100 }
        ];

        let stepIndex = 0;
        const interval = setInterval(() => {
            if (stepIndex < steps.length) {
                if (stepText) stepText.textContent = steps[stepIndex].text;
                if (progressBar) progressBar.style.width = `${steps[stepIndex].pct}%`;
                stepIndex++;
            } else {
                clearInterval(interval);
                setTimeout(() => {
                    if (progressBox) progressBox.classList.add('hidden');
                    currentAnalysisResult = analyzeText(textToAnalyze);
                    if (currentAnalysisResult) {
                        displayAssessment(currentAnalysisResult);
                    }
                }, 150);
            }
        }, 120);
    }

    function clearInputs() {
        playSound('click');
        const messageInput = document.getElementById('messageInput');
        const urlInput = document.getElementById('urlInput');
        const phoneInput = document.getElementById('phoneInput');
        const resultSection = document.getElementById('assessmentResult');

        if (messageInput) messageInput.value = '';
        if (urlInput) urlInput.value = '';
        if (phoneInput) phoneInput.value = '';
        if (resultSection) resultSection.classList.add('hidden');

        updateCharCount();
        showToast('All fields cleared', '✨');
    }

    function updateCharCount() {
        const messageInput = document.getElementById('messageInput');
        const charCount = document.getElementById('charCount');
        if (messageInput && charCount) {
            const count = messageInput.value.length;
            charCount.textContent = `${count} character${count === 1 ? '' : 's'}`;
        }
    }

    // =========================================================================
    // 10. TAB SWITCHING SYSTEM
    // =========================================================================
    function switchTab(tabId) {
        playSound('click');
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(btn => {
            const isMatch = btn.dataset.tab === tabId;
            btn.classList.toggle('active', isMatch);
            btn.setAttribute('aria-selected', isMatch ? 'true' : 'false');
        });

        tabContents.forEach(content => {
            content.classList.toggle('active', content.id === tabId);
        });
    }

    // =========================================================================
    // 11. QUIZ / INSTINCT TRAINER ENGINE
    // =========================================================================
    let quizCurrentIndex = 0;
    let quizScore = 0;
    let quizAnswered = false;

    function renderQuizQuestion() {
        const q = QUIZ_QUESTIONS[quizCurrentIndex];
        const bubble = document.getElementById('quizMessageBubble');
        const progress = document.getElementById('quizProgress');
        const feedback = document.getElementById('quizFeedback');
        const nextBtn = document.getElementById('quizNextBtn');
        const scoreElem = document.getElementById('quizScore');

        if (!bubble || !progress) return;

        quizAnswered = false;
        progress.textContent = `Scenario ${quizCurrentIndex + 1} of ${QUIZ_QUESTIONS.length}`;
        if (scoreElem) scoreElem.textContent = quizScore;

        bubble.innerHTML = `
            <span class="bubble-sender">${escapeHtml(q.sender)}</span>
            <p>${escapeHtml(q.message)}</p>
        `;

        if (feedback) feedback.classList.add('hidden');
        if (nextBtn) nextBtn.classList.add('hidden');

        // Enable answer buttons
        const scamBtn = document.getElementById('choiceScamBtn');
        const legitBtn = document.getElementById('choiceLegitBtn');
        if (scamBtn) scamBtn.disabled = false;
        if (legitBtn) legitBtn.disabled = false;
    }

    function handleQuizChoice(userChoseScam) {
        if (quizAnswered) return;
        quizAnswered = true;

        const q = QUIZ_QUESTIONS[quizCurrentIndex];
        const isCorrect = userChoseScam === q.isScam;
        const feedback = document.getElementById('quizFeedback');
        const nextBtn = document.getElementById('quizNextBtn');
        const scoreElem = document.getElementById('quizScore');

        const scamBtn = document.getElementById('choiceScamBtn');
        const legitBtn = document.getElementById('choiceLegitBtn');
        if (scamBtn) scamBtn.disabled = true;
        if (legitBtn) legitBtn.disabled = true;

        if (isCorrect) {
            quizScore++;
            if (scoreElem) scoreElem.textContent = quizScore;
            playSound('success');
            if (feedback) {
                feedback.className = 'quiz-feedback correct';
                feedback.innerHTML = `<strong>✅ Correct Analysis!</strong> ${escapeHtml(q.explanation)}`;
                feedback.classList.remove('hidden');
            }
        } else {
            playSound('alert-danger');
            if (feedback) {
                feedback.className = 'quiz-feedback incorrect';
                feedback.innerHTML = `<strong>❌ Threat Missed!</strong> ${escapeHtml(q.explanation)}`;
                feedback.classList.remove('hidden');
            }
        }

        if (nextBtn) {
            nextBtn.classList.remove('hidden');
            if (quizCurrentIndex === QUIZ_QUESTIONS.length - 1) {
                nextBtn.textContent = 'Restart Training ↺';
            } else {
                nextBtn.textContent = 'Next Scenario →';
            }
        }
    }

    function handleQuizNext() {
        playSound('click');
        quizCurrentIndex++;
        if (quizCurrentIndex >= QUIZ_QUESTIONS.length) {
            // Completed
            quizCurrentIndex = 0;
            quizScore = 0;
        }
        renderQuizQuestion();
    }

    // =========================================================================
    // 12. INITIALIZATION & EVENT LISTENERS
    // =========================================================================
    document.addEventListener('DOMContentLoaded', () => {
        // Tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                switchTab(btn.dataset.tab);
            });
        });

        // Message input character counter
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.addEventListener('input', updateCharCount);
        }

        // Action Buttons
        const analyzeBtn = document.getElementById('analyzeBtn');
        if (analyzeBtn) analyzeBtn.addEventListener('click', executeScan);

        const clearBtn = document.getElementById('clearBtn');
        if (clearBtn) clearBtn.addEventListener('click', clearInputs);

        // Paste from clipboard button
        const pasteBtn = document.getElementById('pasteClipboardBtn');
        if (pasteBtn && navigator.clipboard) {
            pasteBtn.addEventListener('click', async () => {
                playSound('click');
                try {
                    const text = await navigator.clipboard.readText();
                    if (text && messageInput) {
                        messageInput.value = text;
                        updateCharCount();
                        showToast('Pasted from clipboard!', '📋');
                    }
                } catch (_) {
                    showToast('Clipboard access was not granted.', '⚠️');
                }
            });
        }

        // Quick Preset Buttons
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                playSound('click');
                const presetKey = btn.dataset.preset;
                if (PRESETS[presetKey] && messageInput) {
                    messageInput.value = PRESETS[presetKey];
                    updateCharCount();
                    switchTab('messageTab');
                    showToast(`Loaded: ${btn.textContent.trim()}`, '⚡');
                    // Automatically trigger analysis for seamless demo
                    executeScan();
                }
            });
        });

        // Copy Report Button
        const copyReportBtn = document.getElementById('copyReportBtn');
        if (copyReportBtn) {
            copyReportBtn.addEventListener('click', () => {
                playSound('click');
                if (!currentAnalysisResult) return;
                const report = `[ScamShield AI Threat Report]\nThreat Level: ${currentAnalysisResult.level} (${currentAnalysisResult.score}/100)\nAssessment: ${currentAnalysisResult.headline}\nFindings:\n${currentAnalysisResult.flags.map(f => `- ${f.title}: ${f.desc}`).join('\n')}\nRecommended Action:\n${currentAnalysisResult.protocols.join('\n')}\nAnalyzed on ScamShield AI`;

                if (navigator.clipboard) {
                    navigator.clipboard.writeText(report).then(() => {
                        showToast('Threat report copied to clipboard!', '📋');
                    }).catch(() => {
                        showToast('Could not copy to clipboard.', '⚠️');
                    });
                }
            });
        }

        // Save to History Button
        const saveHistoryBtn = document.getElementById('saveHistoryBtn');
        if (saveHistoryBtn) {
            saveHistoryBtn.addEventListener('click', () => {
                playSound('click');
                if (currentAnalysisResult) {
                    saveToHistory(currentAnalysisResult);
                }
            });
        }

        // Clear History Button
        const clearHistoryBtn = document.getElementById('clearHistoryBtn');
        if (clearHistoryBtn) {
            clearHistoryBtn.addEventListener('click', () => {
                playSound('click');
                clearHistory();
            });
        }

        // Sound Toggle Button
        const soundBtn = document.getElementById('soundToggleBtn');
        if (soundBtn) {
            soundBtn.addEventListener('click', () => {
                soundEnabled = !soundEnabled;
                try {
                    localStorage.setItem('scamshield_sound', soundEnabled.toString());
                } catch (_) {}
                soundBtn.title = soundEnabled ? 'Sound Effects: On' : 'Sound Effects: Muted';
                soundBtn.style.opacity = soundEnabled ? '1' : '0.4';
                showToast(soundEnabled ? 'Sound effects enabled' : 'Sound effects muted', soundEnabled ? '🔊' : '🔇');
                if (soundEnabled) playSound('click');
            });
        }

        // Quiz Buttons
        const choiceScamBtn = document.getElementById('choiceScamBtn');
        if (choiceScamBtn) {
            choiceScamBtn.addEventListener('click', () => handleQuizChoice(true));
        }

        const choiceLegitBtn = document.getElementById('choiceLegitBtn');
        if (choiceLegitBtn) {
            choiceLegitBtn.addEventListener('click', () => handleQuizChoice(false));
        }

        const quizNextBtn = document.getElementById('quizNextBtn');
        if (quizNextBtn) {
            quizNextBtn.addEventListener('click', handleQuizNext);
        }

        // Initialize Quiz and History
        renderQuizQuestion();
        updateHistoryUI();
        updateCharCount();
    });
})();