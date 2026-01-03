// Liteware Authentication Server v3.0 - Complete
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();

// ========================================
// CONFIGURATION
// ========================================
const whitelistedIPs = new Set(['::1', '127.0.0.1', '::ffff:127.0.0.1']);
const rateLimitStore = new Map();
const bannedIPs = new Set();
const bannedHWIDs = new Set();
const activeSessions = new Map();

const RATE_LIMIT_WINDOW = 60000;
const MAX_REQUESTS = 100;

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

const getIP = (req) => req.ip || req.connection?.remoteAddress || 'unknown';
const genToken = () => crypto.randomBytes(32).toString('hex');

const sign = (data, challenge) => {
    const ts = Date.now().toString();
    const sig = crypto.createHmac('sha256', RESPONSE_KEY)
        .update(JSON.stringify(data) + '|' + (challenge || '') + '|' + ts)
        .digest('hex');
    return { ...data, _sig: sig, _ts: ts, _challenge: challenge || '' };
};

// ========================================
// MIDDLEWARE
// ========================================
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));

// Rate limiting (skip for whitelisted)
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
// OWNER KEY ENDPOINTS
// ========================================
app.post('/auth/get-owner-key', (req, res) => {
    res.json({ success: true, owner_key: ownerKey.key, next_rotation: ownerKey.nextRotation });
});

app.post('/auth/get-owner-key-by-hwid', (req, res) => {
    res.json({ success: true, owner_key: ownerKey.key, next_rotation: ownerKey.nextRotation });
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
// ADMIN: GENERATE KEY
// ========================================
app.post('/auth/admin/generate-key', (req, res) => {
    const { duration_days = 30, owner_key: reqOwnerKey } = req.body;
    
    // Allow generation without owner key for admin panel, or verify if provided
    if (reqOwnerKey && reqOwnerKey !== ownerKey.key) {
        return res.json({ success: false, message: 'Invalid owner key' });
    }
    
    const key = `LITE-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
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
        whitelisted_ips: whitelistedIPs.size
    });
});

app.post('/auth/admin/security-stats', (req, res) => {
    res.json({
        success: true,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        whitelisted_ips: whitelistedIPs.size,
        active_sessions: activeSessions.size,
        rate_limited: rateLimitStore.size
    });
});

app.post('/auth/admin/get-all-status', (req, res) => {
    res.json({
        success: true,
        server: !serverDisabled,
        auth: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_lock: websiteLocked
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
// EMERGENCY RESET
// ========================================
app.post('/auth/emergency-reset', (req, res) => {
    bannedIPs.clear();
    bannedHWIDs.clear();
    rateLimitStore.clear();
    serverDisabled = false;
    maintenanceMode = false;
    lockdownMode = false;
    websiteLocked = false;
    authEnabled = true;
    res.json({ success: true, message: 'Emergency reset complete' });
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
