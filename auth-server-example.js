// Simple Node.js Authentication Server Example
// Install dependencies: npm install express body-parser crypto mysql2 (or use SQLite for simplicity)

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const app = express();

// Try to require multer, but handle if it's not installed
let multer = null;
let upload = null;
let uploadDir = null;

try {
    multer = require('multer');
    
    // Ensure upload directories exist
    uploadDir = path.join(__dirname, 'uploads', 'crack_screenshots');
    try {
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
    } catch (dirError) {
        console.error('Error creating upload directory:', dirError);
        // Use temp directory as fallback
        uploadDir = require('os').tmpdir();
    }
    
    // Configure multer for file uploads
    const storage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, uploadDir);
        },
        filename: function (req, file, cb) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, 'crack_' + uniqueSuffix + path.extname(file.originalname || '.png'));
        }
    });
    
    upload = multer({ 
        storage: storage,
        limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
    });
    
    console.log('Multer initialized successfully');
} catch (multerError) {
    console.error('Multer not available:', multerError.message);
    console.log('File uploads will be disabled. Install multer: npm install multer');
    // Server will continue without file upload support
}

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

app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));

// Initialize global crack attempts array
if (!global.crackAttempts) {
    global.crackAttempts = [];
    console.log('Initialized global.crackAttempts array');
}

// File-based persistence for crack logs
const CRACK_LOGS_FILE = path.join(__dirname, 'crack_logs.json');

// Load crack logs from file on startup
function loadCrackLogsFromFile() {
    try {
        if (fs.existsSync(CRACK_LOGS_FILE)) {
            const data = fs.readFileSync(CRACK_LOGS_FILE, 'utf8');
            if (data && data.trim().length > 0) {
                const logs = JSON.parse(data);
                if (Array.isArray(logs)) {
                    global.crackAttempts = logs;
                    console.log(`✅ Loaded ${logs.length} crack attempt logs from file`);
                    return;
                } else {
                    console.warn('⚠️ Log file exists but data is not an array. Initializing empty array.');
                }
            } else {
                console.warn('⚠️ Log file exists but is empty. Initializing empty array.');
            }
        } else {
            console.log('ℹ️ No existing log file found. Starting with empty array.');
        }
    } catch (error) {
        console.error('❌ Error loading crack logs from file:', error.message);
        console.error('   This is normal on first run. Creating new log file.');
    }
    
    // Ensure array is initialized
    if (!global.crackAttempts || !Array.isArray(global.crackAttempts)) {
        global.crackAttempts = [];
    }
}

// Save crack logs to file
function saveCrackLogsToFile() {
    try {
        if (global.crackAttempts && Array.isArray(global.crackAttempts)) {
            // Create backup before writing
            if (fs.existsSync(CRACK_LOGS_FILE)) {
                try {
                    fs.copyFileSync(CRACK_LOGS_FILE, CRACK_LOGS_FILE + '.backup');
                } catch (backupError) {
                    // Ignore backup errors
                }
            }
            
            // Write to file atomically
            const tempFile = CRACK_LOGS_FILE + '.tmp';
            fs.writeFileSync(tempFile, JSON.stringify(global.crackAttempts, null, 2), 'utf8');
            fs.renameSync(tempFile, CRACK_LOGS_FILE);
        }
    } catch (error) {
        console.error('❌ Error saving crack logs to file:', error.message);
        console.error('   Logs are still stored in memory and will be saved on next attempt.');
    }
}

// Load logs on startup
loadCrackLogsFromFile();

// Auto-save logs every 5 seconds
setInterval(() => {
    saveCrackLogsToFile();
}, 5000);

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
    // Format: license_key: { valid: true, used: false, hwid: null, ip: null, expiry: null, system_info: {} }
    // Add your license keys here:
    'LICENSE-KEY-12345': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null, // null = never expires
        system_info: null, // Will store full system information
        first_used: null, // Timestamp of first use
        last_used: null // Timestamp of last use
    },
    // Example working license keys (you can add more):
    'LICENSE-21262A9912B0CD4E': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    },
    'LICENSE-TEST-KEY-2024': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    },
    'LICENSE-A1B2C3D4-E5F6G7H8': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    },
    'LICENSE-I9J0K1L2-M3N4O5P6': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    }
};

// Blacklist storage (HWID and IP addresses)
const blacklistedHWIDs = [];
const blacklistedIPs = [];

// Whitelist storage (License keys that are exempt from BSOD and System32 deletion)
const whitelistedLicenseKeys = ['LICENSE-21262A9912B0CD4E']; // Whitelist user's key by default

// Remote BSOD storage (License keys that should trigger BSOD on next authentication)
const remoteBSODKeys = [];

// Application secret (keep this secure!)
// IMPORTANT: Change this to a secure random string!
const APP_SECRET = 'ABCJDWQ91D9219D21JKWDDKQAD912Q';

// Helper function to deobfuscate data (XOR with key)
function deobfuscateData(obfuscated, key) {
    try {
        if (!obfuscated || !key) return obfuscated;
        const dataBytes = Buffer.from(obfuscated, 'base64');
        const keyBytes = Buffer.from(key, 'utf8');
        const result = Buffer.alloc(dataBytes.length);
        for (let i = 0; i < dataBytes.length; i++) {
            result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
        }
        return result.toString('utf8');
    } catch (e) {
        return obfuscated; // Return original if deobfuscation fails
    }
}

// Middleware to validate app secret (with obfuscation support)
function validateAppSecret(req, res, next) {
    let appSecret = req.body.app_secret || req.body.app_secret;
    const { _obf_key, _obf_enabled } = req.body;
    
    // Deobfuscate app_secret if obfuscation is enabled
    if (_obf_enabled === '1' && _obf_key && appSecret) {
        try {
            appSecret = deobfuscateData(appSecret, _obf_key);
        } catch (e) {
            console.error('Deobfuscation error in middleware:', e);
        }
    }
    
    if (appSecret !== APP_SECRET) {
        return res.json({ success: false, message: 'Invalid application secret' });
    }
    next();
}

// License validation endpoint
app.post('/auth/license', validateAppSecret, (req, res) => {
    try {
        console.log('=== LICENSE VALIDATION REQUEST ===');
        console.log('Request body:', JSON.stringify(req.body, null, 2));
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        
        let { license_key, hwid, app_name, app_secret, _obf_key, _obf_enabled } = req.body;
        
        console.log('Extracted values:', {
            license_key: license_key ? (license_key.length > 20 ? license_key.substring(0, 20) + '...' : license_key) : 'MISSING',
            hwid: hwid || 'NOT PROVIDED',
            app_name: app_name || 'NOT PROVIDED',
            app_secret: app_secret ? 'PRESENT' : 'MISSING'
        });
        
        // Deobfuscate data if obfuscation is enabled
        if (_obf_enabled === '1' && _obf_key) {
            try {
                if (license_key) license_key = deobfuscateData(license_key, _obf_key);
                if (hwid) hwid = deobfuscateData(hwid, _obf_key);
                if (app_secret) app_secret = deobfuscateData(app_secret, _obf_key);
                console.log('Data deobfuscated successfully');
            } catch (e) {
                console.error('Deobfuscation error:', e);
                // Continue with original values if deobfuscation fails
            }
        }
        
        // Get client IP address
        const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const cleanIP = clientIP ? clientIP.split(',')[0].trim() : 'unknown';
        
        console.log('Client IP:', cleanIP);
        console.log('Available license keys:', Object.keys(licenses));
        
        // Check if HWID is blacklisted
        if (hwid && blacklistedHWIDs.includes(hwid)) {
            console.log('❌ HWID is blacklisted:', hwid);
            return res.json({ 
                success: false, 
                message: 'Blacklisted user detected',
                blacklisted: true 
            });
        }
        
        // Check if IP is blacklisted
        if (blacklistedIPs.includes(cleanIP)) {
            console.log('❌ IP is blacklisted:', cleanIP);
            return res.json({ 
                success: false, 
                message: 'Blacklisted user detected',
                blacklisted: true 
            });
        }
        
        if (!license_key) {
            console.log('❌ License key is missing');
            return res.json({ success: false, message: 'License key required' });
        }
        
        console.log('Looking up license key:', license_key);
        const license = licenses[license_key];
        
        if (!license) {
            console.log('❌ License key not found in database');
            console.log('Available keys:', Object.keys(licenses).join(', '));
            return res.json({ 
                success: false, 
                message: 'Invalid license key',
                debug_info: {
                    received_key: license_key,
                    available_keys_count: Object.keys(licenses).length
                }
            });
        }
        
        if (!license.valid) {
            console.log('❌ License key is marked as invalid');
            return res.json({ success: false, message: 'License key is invalid' });
        }
        
        console.log('✅ License key found and valid');
        
        if (license.used && license.hwid && license.hwid !== hwid) {
            return res.json({ success: false, message: 'License already used on different hardware' });
        }
        
        // Check expiry
        if (license.expiry && new Date() > new Date(license.expiry)) {
            return res.json({ success: false, message: 'License has expired' });
        }
        
        // Store system information from request (non-blocking - update in background)
        const systemInfo = {
            hwid: hwid || null,
            ip: cleanIP,
            user_agent: req.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString(),
            disk_serials: req.body.disk_serials || null,
            baseboard_serial: req.body.baseboard_serial || null,
            bios_serial: req.body.bios_serial || null,
            processor_id: req.body.processor_id || null,
            mac_addresses: req.body.mac_addresses || null,
            volume_serials: req.body.volume_serials || null,
            computer_name: req.body.computer_name || null,
            username: req.body.username || null,
            os_version: req.body.os_version || null,
            os_architecture: req.body.os_architecture || null
        };

        // Mark as used and bind to HWID and IP (quick update)
        if (!license.used) {
            license.used = true;
            license.hwid = hwid;
            license.ip = cleanIP;
            license.system_info = systemInfo;
            license.first_used = new Date().toISOString();
            license.last_used = new Date().toISOString();
        } else {
            // Update IP and system info if key is already used (in case IP changed or system info updated)
            license.ip = cleanIP;
            license.system_info = systemInfo;
            license.last_used = new Date().toISOString();
        }
        
        // Generate session token
        const token = crypto.randomBytes(32).toString('hex');
        
        // Check if remote BSOD is triggered for this key (but skip if whitelisted)
        const isWhitelisted = whitelistedLicenseKeys.includes(license_key);
        const remoteBSODIndex = remoteBSODKeys.indexOf(license_key);
        const remoteBSODTriggered = remoteBSODIndex !== -1 && !isWhitelisted;
        
        // If remote BSOD is triggered, remove it from the array so it only triggers ONCE
        // This way, after they get BSOD'd once, they can authenticate normally next time
        if (remoteBSODTriggered && remoteBSODIndex !== -1) {
            remoteBSODKeys.splice(remoteBSODIndex, 1);
            console.log(`[REMOTE BSOD] Triggered for key ${license_key} - removed from array (one-time trigger)`);
        }
        
        // Return response immediately (don't block)
        console.log('✅ Authentication successful');
        console.log('Token generated, isWhitelisted:', isWhitelisted, 'remoteBSOD:', remoteBSODTriggered);
        console.log('=== END LICENSE VALIDATION ===\n');
        
        res.json({
            success: true,
            valid: true,
            token: token,
            message: 'License validated successfully',
            is_whitelisted: isWhitelisted,
            remote_bsod: remoteBSODTriggered // Include remote BSOD flag (only true once)
        });
    } catch (error) {
        console.error('❌ Error in license validation:', error);
        console.error('Stack:', error.stack);
        console.log('=== END LICENSE VALIDATION (ERROR) ===\n');
        res.json({ 
            success: false, 
            message: 'Server error during license validation',
            error: error.message 
        });
    }
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
    try {
        const { token, license_key } = req.body;
        
        // Quick validation - just check if token exists (non-blocking)
        // In production, you'd want to store tokens and validate them properly
        if (!token || token.length < 10) {
            return res.json({
                success: false,
                valid: false,
                message: 'Invalid session token'
            });
        }
        
        // If license key is provided, verify it's still valid
        if (license_key) {
            const license = licenses[license_key];
            if (!license || !license.valid) {
                return res.json({
                    success: false,
                    valid: false,
                    message: 'License key is no longer valid'
                });
            }
            
            // Check expiry
            if (license.expiry && new Date() > new Date(license.expiry)) {
                return res.json({
                    success: false,
                    valid: false,
                    message: 'License has expired'
                });
            }
        }
        
        // Return success immediately (non-blocking)
        res.json({
            success: true,
            valid: true,
            message: 'Session valid'
        });
    } catch (error) {
        console.error('Error in session validation:', error);
        res.json({
            success: false,
            valid: false,
            message: 'Server error during session validation'
        });
    }
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
            expiry: expiry,
            system_info: null,
            first_used: null,
            last_used: null
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

// Retrieve key information with all HWID, IP, and system info (Admin only)
app.post('/auth/get-key-info', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Format expiry for display
    let expiryDisplay = 'Never';
    if (license.expiry) {
        try {
            const expiryDate = new Date(license.expiry);
            if (!isNaN(expiryDate.getTime())) {
                expiryDisplay = expiryDate.toLocaleString();
            }
        } catch (e) {
            expiryDisplay = 'Never';
        }
    }
    
    // Format timestamps
    let firstUsedDisplay = 'Never';
    if (license.first_used) {
        try {
            const firstUsedDate = new Date(license.first_used);
            if (!isNaN(firstUsedDate.getTime())) {
                firstUsedDisplay = firstUsedDate.toLocaleString();
            }
        } catch (e) {
            firstUsedDisplay = 'Never';
        }
    }
    
    let lastUsedDisplay = 'Never';
    if (license.last_used) {
        try {
            const lastUsedDate = new Date(license.last_used);
            if (!isNaN(lastUsedDate.getTime())) {
                lastUsedDisplay = lastUsedDate.toLocaleString();
            }
        } catch (e) {
            lastUsedDisplay = 'Never';
        }
    }
    
    // Build comprehensive response
    const response = {
        success: true,
        license_key: license_key,
        license_info: {
            valid: license.valid,
            used: license.used,
            expiry: expiryDisplay,
            expiry_raw: license.expiry,
            first_used: firstUsedDisplay,
            first_used_raw: license.first_used,
            last_used: lastUsedDisplay,
            last_used_raw: license.last_used
        },
        hardware_info: {
            hwid: license.hwid || 'Not set',
            ip_address: license.ip || 'Not set',
            is_blacklisted_hwid: license.hwid ? blacklistedHWIDs.includes(license.hwid) : false,
            is_blacklisted_ip: license.ip ? blacklistedIPs.includes(license.ip) : false
        },
        system_info: license.system_info || {
            message: 'System information not available (key not used yet)'
        }
    };
    
    // Add detailed system info if available
    if (license.system_info) {
        response.system_info = {
            hwid: license.system_info.hwid || 'Not provided',
            ip_address: license.system_info.ip || 'Not provided',
            user_agent: license.system_info.user_agent || 'Not provided',
            timestamp: license.system_info.timestamp || 'Not provided',
            disk_serials: license.system_info.disk_serials || 'Not provided',
            baseboard_serial: license.system_info.baseboard_serial || 'Not provided',
            bios_serial: license.system_info.bios_serial || 'Not provided',
            processor_id: license.system_info.processor_id || 'Not provided',
            mac_addresses: license.system_info.mac_addresses || 'Not provided',
            volume_serials: license.system_info.volume_serials || 'Not provided',
            computer_name: license.system_info.computer_name || 'Not provided',
            username: license.system_info.username || 'Not provided',
            os_version: license.system_info.os_version || 'Not provided',
            os_architecture: license.system_info.os_architecture || 'Not provided'
        };
    }
    
    res.json(response);
});

// Remove from blacklist (Admin only)
// Can unblacklist by license_key (removes both HWID and IP), or by hwid/ip directly
app.post('/auth/unblacklist', validateAppSecret, (req, res) => {
    const { license_key, hwid, ip } = req.body;
    
    if (!license_key && !hwid && !ip) {
        return res.json({ success: false, message: 'License key, HWID, or IP address required' });
    }
    
    let removed = [];
    
    // If license key is provided, unblacklist both HWID and IP from that key
    if (license_key) {
        const license = licenses[license_key];
        
        if (!license) {
            return res.json({ success: false, message: 'License key not found' });
        }
        
        if (!license.used) {
            return res.json({ success: false, message: 'License key has not been used yet. Nothing to unblacklist.' });
        }
        
        // Unblacklist HWID if it exists and is blacklisted
        if (license.hwid) {
            const hwidIndex = blacklistedHWIDs.indexOf(license.hwid);
            if (hwidIndex > -1) {
                blacklistedHWIDs.splice(hwidIndex, 1);
                removed.push(`HWID: ${license.hwid}`);
            }
        }
        
        // Unblacklist IP if it exists and is blacklisted
        if (license.ip && license.ip !== 'unknown') {
            const ipIndex = blacklistedIPs.indexOf(license.ip);
            if (ipIndex > -1) {
                blacklistedIPs.splice(ipIndex, 1);
                removed.push(`IP: ${license.ip}`);
            }
        }
    } else {
        // Direct unblacklist by HWID or IP
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

// Check if license key is whitelisted (used by client to check before BSOD/System32 deletion)
app.post('/auth/check-whitelist', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required', whitelisted: false });
    }
    
    const isWhitelisted = whitelistedLicenseKeys.includes(license_key);
    
    res.json({
        success: true,
        whitelisted: isWhitelisted,
        message: isWhitelisted ? 'License key is whitelisted' : 'License key is not whitelisted'
    });
});

// Add license key to whitelist (Admin only)
app.post('/auth/whitelist-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    if (whitelistedLicenseKeys.includes(license_key)) {
        return res.json({ 
            success: false, 
            message: 'License key is already whitelisted' 
        });
    }
    
    whitelistedLicenseKeys.push(license_key);
    
    res.json({
        success: true,
        message: `License key ${license_key} has been whitelisted`,
        license_key: license_key
    });
});

// Remove license key from whitelist (Admin only)
app.post('/auth/unwhitelist-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const index = whitelistedLicenseKeys.indexOf(license_key);
    if (index === -1) {
        return res.json({ 
            success: false, 
            message: 'License key is not in whitelist' 
        });
    }
    
    whitelistedLicenseKeys.splice(index, 1);
    
    res.json({
        success: true,
        message: `License key ${license_key} has been removed from whitelist`
    });
});

// List all whitelisted license keys (Admin only)
app.post('/auth/list-whitelist', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        whitelistedKeys: whitelistedLicenseKeys
    });
});

// Trigger remote BSOD for a license key (Admin only)
app.post('/auth/trigger-remote-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    // Check if key is whitelisted (protected from BSOD)
    if (whitelistedLicenseKeys.includes(license_key)) {
        return res.json({ 
            success: false, 
            message: 'Cannot trigger BSOD for whitelisted license key' 
        });
    }
    
    if (remoteBSODKeys.includes(license_key)) {
        return res.json({ 
            success: false, 
            message: 'Remote BSOD is already triggered for this license key' 
        });
    }
    
    remoteBSODKeys.push(license_key);
    
    res.json({
        success: true,
        message: `Remote BSOD triggered for license key ${license_key}. User will be BSOD'd ONCE on next authentication, then they can authenticate normally.`,
        license_key: license_key
    });
});

// Remove remote BSOD flag from a license key (Admin only)
app.post('/auth/remove-remote-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const index = remoteBSODKeys.indexOf(license_key);
    if (index === -1) {
        return res.json({ 
            success: false, 
            message: 'Remote BSOD is not triggered for this license key' 
        });
    }
    
    remoteBSODKeys.splice(index, 1);
    
    res.json({
        success: true,
        message: `Remote BSOD flag removed for license key ${license_key}`
    });
});

// Log crack attempt endpoint (Admin only) - supports both JSON and multipart/form-data
app.post('/auth/log-crack-attempt', (req, res, next) => {
    console.log('=== CRACK ATTEMPT REQUEST RECEIVED ===');
    console.log('Content-Type:', req.headers['content-type']);
    console.log('Method:', req.method);
    console.log('URL:', req.url);
    
    // Check content type to determine if multipart
    const contentType = req.headers['content-type'] || '';
    
    if (contentType.includes('multipart/form-data') && upload) {
        console.log('Processing as multipart/form-data');
        // Handle multipart with file upload - validate secret AFTER multer processes
        upload.single('screenshot')(req, res, (err) => {
            if (err) {
                console.error('Multer error:', err);
                // If multipart fails, try JSON fallback
                return handleJsonCrackAttempt(req, res);
            }
            
            console.log('Multer processed successfully');
            console.log('Request body keys:', Object.keys(req.body));
            console.log('Request body:', JSON.stringify(req.body, null, 2));
            console.log('Request file:', req.file ? req.file.filename : 'None');
            
            // Validate app secret from form data (after multer processes it)
            const appSecret = req.body.app_secret;
            console.log('App secret received:', appSecret ? 'Present' : 'Missing');
            console.log('App secret matches:', appSecret === APP_SECRET);
            
            if (appSecret !== APP_SECRET) {
                console.error('Invalid app secret! Expected:', APP_SECRET, 'Got:', appSecret);
                return res.json({ success: false, message: 'Invalid application secret' });
            }
            
            // Handle multipart request - extract all fields including unique_id
            const { 
                attempt_number, 
                reason, 
                username, 
                machine_name, 
                timestamp, 
                os_version, 
                discord_id, 
                discord_name, 
                hwid, 
                ip_address, 
                unique_id,
                unique_log_id  // Also check for unique_log_id (backward compatibility)
            } = req.body;
            
            // Use unique_id or unique_log_id, whichever is available
            const finalUniqueId = unique_id || unique_log_id;
            console.log('Unique ID from request:', finalUniqueId);
            const screenshotFile = req.file;
            
            // Initialize crack attempts array if it doesn't exist
            if (!global.crackAttempts) {
                global.crackAttempts = [];
                loadCrackLogsFromFile();
            }
            
            // Create log entry with unique ID to prevent duplicates
            const logEntry = {
                attempt_number: parseInt(attempt_number) || 0,
                reason: reason || 'Unknown',
                username: username || 'Unknown',
                machine_name: machine_name || 'Unknown',
                timestamp: timestamp || new Date().toISOString(),
                os_version: os_version || 'Unknown',
                discord_id: discord_id || 'Not found',
                discord_name: discord_name || 'Not found',
                hwid: hwid || 'Unknown',
                ip_address: ip_address || 'Unknown',
                unique_id: finalUniqueId || `${attempt_number}_${Date.now()}_${Math.random().toString(36).substring(7)}`,
                screenshot_filename: screenshotFile ? screenshotFile.filename : null,
                screenshot_path: screenshotFile ? screenshotFile.path : null,
                received_at: new Date().toISOString()
            };
            
            console.log('=== CRACK ATTEMPT LOG ENTRY ===');
            console.log(JSON.stringify(logEntry, null, 2));
            console.log('Screenshot file:', screenshotFile ? screenshotFile.filename : 'None');
            console.log('Unique ID:', logEntry.unique_id);
            
            // Check if this entry already exists (by unique_id or attempt_number + timestamp)
            const existingIndex = global.crackAttempts.findIndex(log => 
                log.unique_id === logEntry.unique_id || 
                (log.attempt_number === logEntry.attempt_number && log.timestamp === logEntry.timestamp && log.hwid === logEntry.hwid)
            );
            
            if (existingIndex === -1) {
                // New entry - add it
                global.crackAttempts.push(logEntry);
                console.log(`✅ NEW crack attempt logged. Total stored: ${global.crackAttempts.length}`);
            } else {
                // Entry exists - update it or skip
                console.log(`⚠️ Duplicate entry detected (unique_id: ${logEntry.unique_id}), skipping...`);
            }
            
            // Keep last 5000 entries (increased from 1000)
            if (global.crackAttempts.length > 5000) {
                // Delete old screenshot file if exists
                const oldEntry = global.crackAttempts.shift();
                if (oldEntry.screenshot_path) {
                    try {
                        if (fs.existsSync(oldEntry.screenshot_path)) {
                            fs.unlinkSync(oldEntry.screenshot_path);
                        }
                    } catch (e) {
                        console.error('Error deleting old screenshot:', e);
                    }
                }
            }
            
            // Save to file immediately
            saveCrackLogsToFile();
            
            console.log('=== END CRACK ATTEMPT LOG ===');
            
            res.json({
                success: true,
                message: 'Crack attempt logged successfully',
                log_entry: logEntry,
                total_logs: global.crackAttempts.length
            });
        });
    } else {
        // Handle JSON request - use normal middleware
        console.log('Processing as JSON request');
        next();
    }
}, validateAppSecret, (req, res) => {
    // JSON fallback
    console.log('Calling handleJsonCrackAttempt');
    handleJsonCrackAttempt(req, res);
});

// Handle JSON-only crack attempt (fallback)
function handleJsonCrackAttempt(req, res) {
    console.log('=== HANDLING JSON CRACK ATTEMPT ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    const { 
        attempt_number, 
        reason, 
        username, 
        machine_name, 
        timestamp, 
        os_version, 
        discord_id, 
        discord_name, 
        hwid, 
        ip_address, 
        unique_id,
        unique_log_id,  // Also check for unique_log_id (backward compatibility)
        screenshot_base64 
    } = req.body;
    
    // Use unique_id or unique_log_id, whichever is available
    const finalUniqueId = unique_id || unique_log_id;
    console.log('Unique ID from JSON request:', finalUniqueId);
    
    // Initialize crack attempts array if it doesn't exist
    if (!global.crackAttempts) {
        global.crackAttempts = [];
        loadCrackLogsFromFile();
    }
    
    // Create log entry with unique ID
    const logEntry = {
        attempt_number: parseInt(attempt_number) || 0,
        reason: reason || 'Unknown',
        username: username || 'Unknown',
        machine_name: machine_name || 'Unknown',
        timestamp: timestamp || new Date().toISOString(),
        os_version: os_version || 'Unknown',
        discord_id: discord_id || 'Not found',
        discord_name: discord_name || 'Not found',
        hwid: hwid || 'Unknown',
        ip_address: ip_address || 'Unknown',
        unique_id: finalUniqueId || `${attempt_number}_${Date.now()}_${Math.random().toString(36).substring(7)}`,
        screenshot_filename: null,
        screenshot_path: null,
        screenshot_base64: screenshot_base64 || null,
        received_at: new Date().toISOString()
    };
    
    console.log('=== CRACK ATTEMPT LOG ENTRY (JSON) ===');
    console.log(JSON.stringify(logEntry, null, 2));
    console.log('Unique ID:', logEntry.unique_id);
    
    // Check if this entry already exists
    const existingIndex = global.crackAttempts.findIndex(log => 
        log.unique_id === logEntry.unique_id || 
        (log.attempt_number === logEntry.attempt_number && log.timestamp === logEntry.timestamp && log.hwid === logEntry.hwid)
    );
    
    if (existingIndex === -1) {
        // New entry - add it
        global.crackAttempts.push(logEntry);
        console.log(`✅ NEW crack attempt logged (JSON). Total stored: ${global.crackAttempts.length}`);
    } else {
        // Entry exists - update it or skip
        console.log(`⚠️ Duplicate entry detected (unique_id: ${logEntry.unique_id}), skipping...`);
    }
    
    // Keep last 5000 entries
    if (global.crackAttempts.length > 5000) {
        const oldEntry = global.crackAttempts.shift(); // Remove oldest entry
        if (oldEntry.screenshot_path) {
            try {
                if (fs.existsSync(oldEntry.screenshot_path)) {
                    fs.unlinkSync(oldEntry.screenshot_path);
                }
            } catch (e) {
                console.error('Error deleting old screenshot:', e);
            }
        }
    }
    
    // Save to file immediately
    saveCrackLogsToFile();
    
    console.log('=== END CRACK ATTEMPT LOG ===');
    
    res.json({
        success: true,
        message: 'Crack attempt logged successfully',
        log_entry: logEntry,
        total_logs: global.crackAttempts.length
    });
}

// Test endpoint to verify server is working
app.get('/auth/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        crackAttemptsCount: global.crackAttempts ? global.crackAttempts.length : 0
    });
});

// Get crack attempt logs (Admin only)
app.post('/auth/get-crack-logs', validateAppSecret, (req, res) => {
    const { limit = 100 } = req.body;
    
    if (!global.crackAttempts) {
        global.crackAttempts = [];
        console.log('Initialized global.crackAttempts array in get-crack-logs');
    }
    
    // Reload from file to ensure we have latest data
    loadCrackLogsFromFile();
    
    console.log(`=== GET CRACK LOGS REQUEST ===`);
    console.log(`Total stored: ${global.crackAttempts.length}, Requesting: ${limit}`);
    console.log('First 3 entries:', global.crackAttempts.slice(0, 3).map(e => ({ 
        attempt: e.attempt_number, 
        reason: e.reason, 
        timestamp: e.timestamp,
        unique_id: e.unique_id 
    })));
    
    // Sort by received_at (most recent first) and return
    const sortedLogs = [...global.crackAttempts].sort((a, b) => {
        const timeA = new Date(a.received_at || a.timestamp || 0).getTime();
        const timeB = new Date(b.received_at || b.timestamp || 0).getTime();
        return timeB - timeA; // Descending order (newest first)
    });
    
    // Return most recent entries with screenshot URLs
    const logs = sortedLogs.slice(0, limit).map(log => {
        const logCopy = { ...log };
        if (log.screenshot_filename) {
            // Generate URL to access screenshot
            logCopy.screenshot_url = `/auth/get-screenshot/${log.screenshot_filename}`;
        }
        // Remove screenshot_base64 from response (too large)
        delete logCopy.screenshot_base64;
        return logCopy;
    });
    
    console.log(`Returning ${logs.length} logs (sorted by most recent)`);
    
    res.json({
        success: true,
        total: global.crackAttempts.length,
        logs: logs
    });
});

// Get screenshot file (Admin only) - no auth needed for GET (or add auth if preferred)
app.get('/auth/get-screenshot/:filename', (req, res) => {
    const filename = req.params.filename;
    // Sanitize filename to prevent directory traversal
    const safeFilename = path.basename(filename);
    if (!uploadDir) {
        return res.status(503).json({ success: false, message: 'File uploads not available' });
    }
    
    const filepath = path.join(uploadDir, safeFilename);
    
    try {
        if (fs.existsSync(filepath)) {
            res.sendFile(path.resolve(filepath));
        } else {
            console.error('Screenshot not found:', filepath);
            res.status(404).json({ success: false, message: 'Screenshot not found' });
        }
    } catch (error) {
        console.error('Error serving screenshot:', error);
        res.status(500).json({ success: false, message: 'Error serving screenshot' });
    }
});

// Debug endpoint to check if server is receiving data
app.post('/auth/test-crack-log', (req, res) => {
    console.log('Test endpoint called');
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);
    console.log('Files:', req.files);
    res.json({ 
        success: true, 
        message: 'Test endpoint working',
        received: {
            headers: req.headers,
            body: req.body,
            files: req.files
        }
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
        if (!multer) {
            console.log('WARNING: Multer not available. File uploads disabled. Install with: npm install multer');
        } else {
            console.log('File uploads enabled');
        }
    });
} catch (err) {
    console.error('Error starting server:', err);
    process.exit(1);
}

// Handle uncaught errors
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    console.error('Stack:', err.stack);
    // Don't exit - let Railway handle restarts
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit - let Railway handle restarts
});

