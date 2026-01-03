// Liteware Authentication Server v3.0
// Minimal, stable version

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ========================================
// CONFIGURATION - DEFINE ALL CONSTANTS FIRST
// ========================================

// IP Whitelist
const whitelistedIPs = new Set([
    '::1',
    '127.0.0.1',
    '::ffff:127.0.0.1'
]);

// Security stores
const rateLimitStore = new Map();
const bannedIPs = new Set();
const bannedHWIDs = new Set();
const activeSessions = new Map();

// Security constants
const RATE_LIMIT_WINDOW = 60000;
const MAX_REQUESTS_PER_WINDOW = 30;
const BAN_DURATION = 3600000;

// Server state
let serverDisabled = false;
let maintenanceMode = false;

// Application secret
const APP_SECRET = 'ABCJDWQ91D9219D21JKWDDKQAD912Q';

// Response signing key (must match client)
const RESPONSE_SIGNING_KEY = 'LITEWARE_SECRET_KEY_2026_V3';

// License database
const licenses = {
    'LITE-TEST-1234-5678': {
        valid: true,
        hwid: null,
        activated: false,
        created: Date.now(),
        expires: Date.now() + (365 * 24 * 60 * 60 * 1000)
    },
    'LITE-DEMO-AAAA-BBBB': {
        valid: true,
        hwid: null,
        activated: false,
        created: Date.now(),
        expires: Date.now() + (30 * 24 * 60 * 60 * 1000)
    }
};

// Owner key data
let ownerKeyData = {
    key: crypto.randomBytes(32).toString('hex'),
    created: Date.now(),
    nextRotation: Date.now() + (24 * 60 * 60 * 1000)
};

// ========================================
// HELPER FUNCTIONS
// ========================================

function isIPWhitelisted(ip) {
    if (!ip) return false;
    const cleanIP = ip.split(',')[0].trim();
    return whitelistedIPs.has(cleanIP) || 
           whitelistedIPs.has(cleanIP.replace('::ffff:', ''));
}

function getClientIP(req) {
    return req.ip || req.connection?.remoteAddress || 'unknown';
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function signResponse(responseData, clientChallenge) {
    const timestamp = Date.now().toString();
    const dataToSign = JSON.stringify(responseData) + '|' + (clientChallenge || '') + '|' + timestamp;
    const signature = crypto.createHmac('sha256', RESPONSE_SIGNING_KEY)
        .update(dataToSign)
        .digest('hex');
    
    return {
        ...responseData,
        _sig: signature,
        _ts: timestamp,
        _challenge: clientChallenge || ''
    };
}

// ========================================
// MIDDLEWARE
// ========================================

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// Body parser
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));

// Rate limiting
app.use((req, res, next) => {
    const ip = getClientIP(req);
    
    // Skip for whitelisted IPs
    if (isIPWhitelisted(ip)) {
        return next();
    }
    
    // Check if banned
    if (bannedIPs.has(ip)) {
        return res.status(403).json({ success: false, message: 'IP banned' });
    }
    
    // Rate limit check
    const now = Date.now();
    const record = rateLimitStore.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
    
    if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + RATE_LIMIT_WINDOW;
    }
    
    record.count++;
    rateLimitStore.set(ip, record);
    
    if (record.count > MAX_REQUESTS_PER_WINDOW) {
        return res.status(429).json({ success: false, message: 'Rate limited' });
    }
    
    next();
});

// ========================================
// HEALTH CHECK ENDPOINTS (NO AUTH REQUIRED)
// ========================================

app.get('/', (req, res) => {
    res.json({ status: 'online', version: '3.0', time: Date.now() });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/auth/health', (req, res) => {
    res.json({ status: 'ok', server_time: Date.now() });
});

// ========================================
// AUTHENTICATION ENDPOINTS
// ========================================

// Validate app secret middleware
function validateAppSecret(req, res, next) {
    const appSecret = req.body.app_secret;
    if (appSecret !== APP_SECRET) {
        return res.status(401).json(signResponse({ success: false, message: 'Invalid app secret' }, req.body._challenge));
    }
    next();
}

// Test endpoint
app.post('/auth/test', (req, res) => {
    res.json(signResponse({ success: true, message: 'Server online', version: '3.0' }, req.body._challenge));
});

// Validate license
app.post('/auth/validate', validateAppSecret, (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (serverDisabled) {
        return res.json(signResponse({ success: false, message: 'Server is disabled' }, _challenge));
    }
    
    if (!license_key) {
        return res.json(signResponse({ success: false, message: 'License key required' }, _challenge));
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json(signResponse({ success: false, message: 'Invalid license key' }, _challenge));
    }
    
    if (!license.valid) {
        return res.json(signResponse({ success: false, message: 'License has been revoked' }, _challenge));
    }
    
    if (license.expires < Date.now()) {
        return res.json(signResponse({ success: false, message: 'License has expired' }, _challenge));
    }
    
    // Check HWID binding
    if (license.hwid && license.hwid !== hwid) {
        return res.json(signResponse({ success: false, message: 'License bound to different hardware' }, _challenge));
    }
    
    // Bind HWID if not already bound
    if (!license.hwid && hwid) {
        license.hwid = hwid;
        license.activated = true;
        console.log(`License ${license_key} bound to HWID: ${hwid}`);
    }
    
    // Generate session token
    const sessionToken = generateSessionToken();
    activeSessions.set(sessionToken, {
        license_key,
        hwid,
        created: Date.now(),
        expires: Date.now() + 3600000
    });
    
    res.json(signResponse({
        success: true,
        message: 'License valid',
        session_token: sessionToken,
        expires: license.expires
    }, _challenge));
});

// Activate license
app.post('/auth/activate', validateAppSecret, (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (!license_key || !hwid) {
        return res.json(signResponse({ success: false, message: 'License key and HWID required' }, _challenge));
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json(signResponse({ success: false, message: 'Invalid license key' }, _challenge));
    }
    
    if (license.hwid && license.hwid !== hwid) {
        return res.json(signResponse({ success: false, message: 'License already bound to different hardware' }, _challenge));
    }
    
    license.hwid = hwid;
    license.activated = true;
    
    const sessionToken = generateSessionToken();
    activeSessions.set(sessionToken, {
        license_key,
        hwid,
        created: Date.now(),
        expires: Date.now() + 3600000
    });
    
    res.json(signResponse({
        success: true,
        message: 'License activated successfully',
        session_token: sessionToken
    }, _challenge));
});

// Heartbeat
app.post('/auth/heartbeat', validateAppSecret, (req, res) => {
    const { session_token, _challenge } = req.body;
    
    const session = activeSessions.get(session_token);
    if (!session) {
        return res.json(signResponse({ success: false, message: 'Invalid session' }, _challenge));
    }
    
    if (session.expires < Date.now()) {
        activeSessions.delete(session_token);
        return res.json(signResponse({ success: false, message: 'Session expired' }, _challenge));
    }
    
    // Extend session
    session.expires = Date.now() + 3600000;
    
    res.json(signResponse({ success: true, message: 'Session valid' }, _challenge));
});

// ========================================
// ADMIN ENDPOINTS
// ========================================

// Get owner key
app.post('/auth/get-owner-key', (req, res) => {
    res.json({
        success: true,
        owner_key: ownerKeyData.key,
        next_rotation: ownerKeyData.nextRotation
    });
});

// Rotate owner key
app.post('/auth/admin/rotate-owner-key', (req, res) => {
    ownerKeyData = {
        key: crypto.randomBytes(32).toString('hex'),
        created: Date.now(),
        nextRotation: Date.now() + (24 * 60 * 60 * 1000)
    };
    
    res.json({
        success: true,
        message: 'Owner key rotated',
        owner_key: ownerKeyData.key,
        next_rotation: ownerKeyData.nextRotation
    });
});

// Generate license key
app.post('/auth/admin/generate-key', (req, res) => {
    const { duration_days = 30 } = req.body;
    
    const key = `LITE-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    
    licenses[key] = {
        valid: true,
        hwid: null,
        activated: false,
        created: Date.now(),
        expires: Date.now() + (duration_days * 24 * 60 * 60 * 1000)
    };
    
    res.json({
        success: true,
        license_key: key,
        expires: licenses[key].expires
    });
});

// List all licenses
app.post('/auth/admin/list-keys', (req, res) => {
    const keys = Object.entries(licenses).map(([key, data]) => ({
        key,
        valid: data.valid,
        activated: data.activated,
        hwid: data.hwid,
        expires: data.expires
    }));
    
    res.json({ success: true, licenses: keys });
});

// Revoke license
app.post('/auth/admin/revoke-key', (req, res) => {
    const { license_key } = req.body;
    
    if (licenses[license_key]) {
        licenses[license_key].valid = false;
        res.json({ success: true, message: 'License revoked' });
    } else {
        res.json({ success: false, message: 'License not found' });
    }
});

// Server status
app.post('/auth/admin/status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        maintenance_mode: maintenanceMode,
        active_sessions: activeSessions.size,
        total_licenses: Object.keys(licenses).length,
        banned_ips: bannedIPs.size,
        uptime: process.uptime()
    });
});

// Enable/disable server
app.post('/auth/admin/toggle-server', (req, res) => {
    serverDisabled = !serverDisabled;
    res.json({ success: true, server_enabled: !serverDisabled });
});

// IP whitelist management
app.post('/auth/admin/whitelist-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) {
        whitelistedIPs.add(ip);
        res.json({ success: true, message: `IP ${ip} whitelisted` });
    } else {
        res.json({ success: false, message: 'IP required' });
    }
});

app.post('/auth/admin/unwhitelist-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) {
        whitelistedIPs.delete(ip);
        res.json({ success: true, message: `IP ${ip} removed from whitelist` });
    } else {
        res.json({ success: false, message: 'IP required' });
    }
});

app.post('/auth/admin/list-whitelisted-ips', (req, res) => {
    res.json({ success: true, whitelisted_ips: Array.from(whitelistedIPs) });
});

app.post('/auth/admin/get-my-ip', (req, res) => {
    const ip = getClientIP(req);
    res.json({ 
        success: true, 
        ip: ip,
        is_whitelisted: isIPWhitelisted(ip)
    });
});

app.post('/auth/admin/whitelist-my-ip', (req, res) => {
    const ip = getClientIP(req);
    whitelistedIPs.add(ip);
    res.json({ success: true, message: `Your IP ${ip} has been whitelisted` });
});

// Ban/unban IP
app.post('/auth/admin/ban-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) {
        bannedIPs.add(ip);
        res.json({ success: true, message: `IP ${ip} banned` });
    } else {
        res.json({ success: false, message: 'IP required' });
    }
});

app.post('/auth/admin/unban-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) {
        bannedIPs.delete(ip);
        res.json({ success: true, message: `IP ${ip} unbanned` });
    } else {
        res.json({ success: false, message: 'IP required' });
    }
});

app.post('/auth/admin/list-banned-ips', (req, res) => {
    res.json({ success: true, banned_ips: Array.from(bannedIPs) });
});

// Stats
app.post('/auth/admin/stats', (req, res) => {
    res.json({
        success: true,
        total_licenses: Object.keys(licenses).length,
        active_licenses: Object.values(licenses).filter(l => l.valid && l.activated).length,
        active_sessions: activeSessions.size,
        banned_ips: bannedIPs.size,
        whitelisted_ips: whitelistedIPs.size
    });
});

// Emergency reset
app.post('/auth/emergency-reset', (req, res) => {
    bannedIPs.clear();
    rateLimitStore.clear();
    serverDisabled = false;
    maintenanceMode = false;
    res.json({ success: true, message: 'Emergency reset complete' });
});

// ========================================
// LEGACY ENDPOINTS (for compatibility)
// ========================================

app.post('/auth/get-owner-key-by-hwid', (req, res) => {
    res.json({
        success: true,
        owner_key: ownerKeyData.key,
        next_rotation: ownerKeyData.nextRotation
    });
});

app.post('/auth/verify-hwid', validateAppSecret, (req, res) => {
    const { hwid, _challenge } = req.body;
    
    // Check if HWID is banned
    if (bannedHWIDs.has(hwid)) {
        return res.json(signResponse({ success: false, message: 'HWID banned' }, _challenge));
    }
    
    res.json(signResponse({ success: true, message: 'HWID valid' }, _challenge));
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`✅ Liteware Auth Server running on port ${PORT}`);
    console.log(`📋 Total licenses: ${Object.keys(licenses).length}`);
    console.log(`🔑 Owner key: ${ownerKeyData.key.substring(0, 16)}...`);
});

// Error handlers
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (reason) => {
    console.error('Unhandled Rejection:', reason);
});
