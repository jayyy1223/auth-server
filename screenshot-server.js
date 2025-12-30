// Screenshot Upload Server
// Run: node screenshot-server.js
// Or deploy to Railway/Heroku/etc.

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const app = express();

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'screenshots');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        // Use metadata to create filename
        const machine = req.body.machine || 'unknown';
        const user = req.body.user || 'unknown';
        const timestamp = req.body.timestamp || new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${machine}_${user}_${timestamp}.png`;
        cb(null, filename);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB max file size
    }
});

// Enable CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Screenshot upload endpoint
app.post('/upload-screenshot', upload.single('file'), (req, res) => {
    try {
        const machine = req.body.machine || 'Unknown';
        const user = req.body.user || 'Unknown';
        const timestamp = req.body.timestamp || new Date().toISOString();
        
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: 'No file uploaded' 
            });
        }

        // Log the crack attempt
        const logEntry = `[${new Date().toISOString()}] CRACK ATTEMPT DETECTED!\n` +
            `  Machine: ${machine}\n` +
            `  User: ${user}\n` +
            `  Timestamp: ${timestamp}\n` +
            `  File: ${req.file.filename}\n` +
            `  Size: ${req.file.size} bytes\n` +
            `  IP: ${req.ip || req.connection.remoteAddress}\n` +
            `  User-Agent: ${req.get('user-agent') || 'Unknown'}\n` +
            `----------------------------------------\n\n`;

        // Append to log file
        const logFile = path.join(__dirname, 'crack_attempts.log');
        fs.appendFileSync(logFile, logEntry, 'utf8');

        // Also log to console
        console.log('\n🚨 CRACK ATTEMPT DETECTED! 🚨');
        console.log(`Machine: ${machine}`);
        console.log(`User: ${user}`);
        console.log(`Timestamp: ${timestamp}`);
        console.log(`Screenshot saved: ${req.file.filename}`);
        console.log(`IP: ${req.ip || req.connection.remoteAddress}\n`);

        res.json({
            success: true,
            message: 'Screenshot uploaded successfully',
            filename: req.file.filename
        });
    } catch (error) {
        console.error('Error uploading screenshot:', error);
        res.status(500).json({
            success: false,
            message: 'Error uploading screenshot: ' + error.message
        });
    }
});

// View all screenshots (for admin)
app.get('/screenshots', (req, res) => {
    try {
        const files = fs.readdirSync(uploadsDir)
            .filter(file => file.endsWith('.png'))
            .map(file => {
                const filePath = path.join(uploadsDir, file);
                const stats = fs.statSync(filePath);
                return {
                    filename: file,
                    size: stats.size,
                    created: stats.birthtime,
                    url: `/screenshots/${file}`
                };
            })
            .sort((a, b) => b.created - a.created); // Newest first

        res.json({
            success: true,
            count: files.length,
            screenshots: files
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Serve screenshot files
app.get('/screenshots/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadsDir, filename);
    
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ success: false, message: 'File not found' });
    }
});

// View log file
app.get('/logs', (req, res) => {
    try {
        const logFile = path.join(__dirname, 'crack_attempts.log');
        if (fs.existsSync(logFile)) {
            const logs = fs.readFileSync(logFile, 'utf8');
            res.type('text/plain');
            res.send(logs);
        } else {
            res.json({ success: false, message: 'No logs yet' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Health check
app.get('/', (req, res) => {
    res.json({
        status: 'Screenshot server running',
        endpoints: {
            upload: 'POST /upload-screenshot',
            list: 'GET /screenshots',
            logs: 'GET /logs'
        }
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`\n✅ Screenshot server running on port ${PORT}`);
    console.log(`📸 Upload endpoint: http://localhost:${PORT}/upload-screenshot`);
    console.log(`📁 Screenshots saved to: ${uploadsDir}\n`);
});

