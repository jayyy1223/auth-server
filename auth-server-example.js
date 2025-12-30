// Simple Node.js Authentication Server Example
// Install dependencies: npm install express body-parser crypto mysql2 (or use SQLite for simplicity)

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();

// Enable CORS for all routes
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// In-memory database (replace with real database like MySQL, MongoDB, or SQLite)
const users = {
    // Format: username: { password_hash, license_keys: [], hwid: null }
    'testuser': {
        password_hash: crypto.createHash('sha256').update('testpass123').digest('hex'),
        license_keys: ['LICENSE-KEY-12345'],
        hwid: null
    }
};

const licenses = {
    // Format: license_key: { valid: true, used: false, hwid: null, ip: null, expiry: null }
    // Add your license keys here:
    'LICENSE-KEY-12345': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null // null = never expires
    },
    // Add more license keys below:
    // 'YOUR-LICENSE-KEY-1': {
    //     valid: true,
    //     used: false,
    //     hwid: null,
    //     expiry: null
    // },
    // 'YOUR-LICENSE-KEY-2': {
    //     valid: true,
    //     used: false,
    //     hwid: null,
    //     expiry: null
    // }
};

// Blacklist storage (HWID and IP addresses)
const blacklistedHWIDs = [];
const blacklistedIPs = [];

// Application secret (keep this secure!)
// IMPORTANT: Change this to a secure random string!
const APP_SECRET = 'ABCJDWQ91D9219D21JKWDDKQAD912Q';

// Middleware to validate app secret
function validateAppSecret(req, res, next) {
    const appSecret = req.body.app_secret || req.body.app_secret;
    if (appSecret !== APP_SECRET) {
        return res.json({ success: false, message: 'Invalid application secret' });
    }
    next();
}

// License validation endpoint
app.post('/auth/license', validateAppSecret, (req, res) => {
    const { license_key, hwid, app_name } = req.body;
    
    // Get client IP address
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const cleanIP = clientIP ? clientIP.split(',')[0].trim() : 'unknown';
    
    // Check if HWID is blacklisted
    if (hwid && blacklistedHWIDs.includes(hwid)) {
        return res.json({ 
            success: false, 
            message: 'Blacklisted user detected',
            blacklisted: true 
        });
    }
    
    // Check if IP is blacklisted
    if (blacklistedIPs.includes(cleanIP)) {
        return res.json({ 
            success: false, 
            message: 'Blacklisted user detected',
            blacklisted: true 
        });
    }
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license || !license.valid) {
        return res.json({ success: false, message: 'Invalid license key' });
    }
    
    if (license.used && license.hwid !== hwid) {
        return res.json({ success: false, message: 'License already used on different hardware' });
    }
    
    // Check expiry
    if (license.expiry && new Date() > new Date(license.expiry)) {
        return res.json({ success: false, message: 'License has expired' });
    }
    
    // Mark as used and bind to HWID and IP
    if (!license.used) {
        license.used = true;
        license.hwid = hwid;
        license.ip = cleanIP;
    } else {
        // Update IP if key is already used (in case IP changed)
        license.ip = cleanIP;
    }
    
    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({
        success: true,
        valid: true,
        token: token,
        message: 'License validated successfully'
    });
});

// Username/Password validation endpoint
app.post('/auth/login', validateAppSecret, (req, res) => {
    const { username, password, hwid, app_name } = req.body;
    
    // Get client IP address
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const cleanIP = clientIP ? clientIP.split(',')[0].trim() : 'unknown';
    
    // Check if HWID is blacklisted
    if (hwid && blacklistedHWIDs.includes(hwid)) {
        return res.json({ 
            success: false, 
            message: 'Blacklisted user detected',
            blacklisted: true 
        });
    }
    
    // Check if IP is blacklisted
    if (blacklistedIPs.includes(cleanIP)) {
        return res.json({ 
            success: false, 
            message: 'Blacklisted user detected',
            blacklisted: true 
        });
    }
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password required' });
    }
    
    const user = users[username];
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Hash password and compare
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    
    if (user.password_hash !== passwordHash) {
        return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check HWID if bound
    if (user.hwid && user.hwid !== hwid) {
        return res.json({ success: false, message: 'Account is bound to different hardware' });
    }
    
    // Bind HWID if not bound
    if (!user.hwid && hwid) {
        user.hwid = hwid;
    }
    
    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({
        success: true,
        valid: true,
        token: token,
        message: 'Login successful'
    });
});

// Session validation endpoint
app.post('/auth/session', validateAppSecret, (req, res) => {
    const { token } = req.body;
    
    // In real implementation, store tokens and check them
    // For now, just return success (you'd want to check if token is valid)
    
    res.json({
        success: true,
        valid: true,
        message: 'Session valid'
    });
});

// License Key Generator Endpoint (Admin only - add authentication in production!)
app.post('/auth/generate-key', validateAppSecret, (req, res) => {
    const { count = 1, prefix = 'LICENSE', keyType = 'lifetime' } = req.body;
    
    const generatedKeys = [];
    
    // Calculate expiry based on key type
    let expiry = null;
    if (keyType === '24hr') {
        // Add 24 hours (86400000 milliseconds) to current time
        const expiryDate = new Date(Date.now() + (24 * 60 * 60 * 1000));
        expiry = expiryDate.toISOString();
    } else if (keyType === 'lifetime') {
        expiry = null; // null = never expires
    }
    
    for (let i = 0; i < count; i++) {
        // Generate a random license key
        const randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
        const licenseKey = `${prefix}-${randomPart}`;
        
        // Add to licenses object
        licenses[licenseKey] = {
            valid: true,
            used: false,
            hwid: null,
            ip: null,
            expiry: expiry
        };
        
        // Format expiry for display
        let expiryDisplay = 'Never';
        if (expiry) {
            try {
                const expiryDate = new Date(expiry);
                if (!isNaN(expiryDate.getTime())) {
                    expiryDisplay = expiryDate.toLocaleString();
                }
            } catch (e) {
                expiryDisplay = 'Never';
            }
        }
        
        generatedKeys.push({
            key: licenseKey,
            type: keyType,
            expiry: expiryDisplay
        });
    }
    
    res.json({
        success: true,
        keys: generatedKeys,
        message: `Generated ${count} ${keyType} license key(s)`
    });
});

// List all license keys (Admin only - use POST with app_secret in body)
app.post('/auth/list-keys', validateAppSecret, (req, res) => {
    const keysList = Object.keys(licenses).map(key => {
        const license = licenses[key];
        return {
            key: key,
            valid: license.valid,
            used: license.used,
            hwid: license.hwid,
            ip: license.ip,
            expiry: license.expiry // Return ISO string, client will format it
        };
    });
    
    res.json({
        success: true,
        total: keysList.length,
        keys: keysList
    });
});

// Reset HWID for a license key (Admin only)
app.post('/auth/reset-hwid', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Reset HWID and mark as unused
    license.hwid = null;
    license.used = false;
    
    res.json({
        success: true,
        message: 'HWID reset successfully',
        license_key: license_key
    });
});

// Delete a license key (Admin only)
app.post('/auth/delete-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    if (!licenses[license_key]) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Delete the license key
    delete licenses[license_key];
    
    res.json({
        success: true,
        message: 'License key deleted successfully',
        license_key: license_key
    });
});

// Blacklist by License Key (Admin only)
// This will blacklist the HWID and IP of whoever used the key
app.post('/auth/blacklist', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    if (!license.used) {
        return res.json({ success: false, message: 'License key has not been used yet. Cannot blacklist unused keys.' });
    }
    
    let added = [];
    
    // Blacklist the HWID if it exists and not already blacklisted
    if (license.hwid && !blacklistedHWIDs.includes(license.hwid)) {
        blacklistedHWIDs.push(license.hwid);
        added.push(`HWID: ${license.hwid}`);
    }
    
    // Blacklist the IP if it exists and not already blacklisted
    if (license.ip && license.ip !== 'unknown' && !blacklistedIPs.includes(license.ip)) {
        blacklistedIPs.push(license.ip);
        added.push(`IP: ${license.ip}`);
    }
    
    if (added.length === 0) {
        return res.json({ 
            success: false, 
            message: 'HWID and IP for this license key are already blacklisted' 
        });
    }
    
    res.json({
        success: true,
        message: `Blacklisted user from license key ${license_key}: ${added.join(', ')}`,
        blacklistedHWIDs: blacklistedHWIDs,
        blacklistedIPs: blacklistedIPs,
        hwid: license.hwid,
        ip: license.ip
    });
});

// List blacklisted HWIDs and IPs (Admin only)
app.post('/auth/list-blacklist', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        blacklistedHWIDs: blacklistedHWIDs,
        blacklistedIPs: blacklistedIPs
    });
});

// Remove from blacklist (Admin only)
app.post('/auth/unblacklist', validateAppSecret, (req, res) => {
    const { hwid, ip } = req.body;
    
    if (!hwid && !ip) {
        return res.json({ success: false, message: 'HWID or IP address required' });
    }
    
    let removed = [];
    
    if (hwid) {
        const index = blacklistedHWIDs.indexOf(hwid);
        if (index > -1) {
            blacklistedHWIDs.splice(index, 1);
            removed.push(`HWID: ${hwid}`);
        }
    }
    
    if (ip) {
        const index = blacklistedIPs.indexOf(ip);
        if (index > -1) {
            blacklistedIPs.splice(index, 1);
            removed.push(`IP: ${ip}`);
        }
    }
    
    if (removed.length === 0) {
        return res.json({ 
            success: false, 
            message: 'HWID or IP not found in blacklist' 
        });
    }
    
    res.json({
        success: true,
        message: `Removed from blacklist: ${removed.join(', ')}`
    });
});

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'Auth server running' });
});

const PORT = process.env.PORT || 3000;

// Error handling for server startup
try {
    app.listen(PORT, () => {
        console.log(`Authentication server running on port ${PORT}`);
    });
} catch (err) {
    console.error('Error starting server:', err);
    process.exit(1);
}

// Handle uncaught errors
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

