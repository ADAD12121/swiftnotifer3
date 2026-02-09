// ========================================
// SWIFT NOTIFIER BACKEND - ULTRA FAST MODE
// 10-second retention - Optimized for real-time scanning
// ========================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================
// CONFIGURATION
// ========================================

const RETENTION_SECONDS = 10; // Keep findings for only 10 seconds
const CLEANUP_INTERVAL = 5;   // Run cleanup every 5 seconds

// ========================================
// MIDDLEWARE
// ========================================

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'], allowedHeaders: ['Content-Type'] }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Rate limiting
const submitLimiter = rateLimit({
    windowMs: 1000,
    max: 100,
    message: { success: false, error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false,
});

const queryLimiter = rateLimit({
    windowMs: 100,
    max: 200,
    message: { success: false, error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false,
});

// ========================================
// DATABASE SETUP
// ========================================

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'findings.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        process.exit(1);
    }
    console.log('✅ Connected to SQLite database');
});

// Enable WAL mode for better concurrent performance
db.run('PRAGMA journal_mode = WAL');
db.run('PRAGMA synchronous = NORMAL');
db.run('PRAGMA cache_size = 10000');
db.configure('busyTimeout', 5000);

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jobId TEXT NOT NULL,
            placeId TEXT NOT NULL,
            pets TEXT NOT NULL,
            rates TEXT,
            timestamp INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(jobId, placeId)
        )
    `, (err) => {
        if (err) {
            console.error('❌ Table creation failed:', err.message);
        } else {
            console.log('✅ Findings table ready');
        }
    });

    db.run('CREATE INDEX IF NOT EXISTS idx_timestamp ON findings(timestamp DESC)');
    db.run('CREATE INDEX IF NOT EXISTS idx_jobId ON findings(jobId)');
    
    // ULTRA FAST CLEANUP: Delete findings older than 10 seconds
    setInterval(() => {
        const cutoffTime = Date.now() - (RETENTION_SECONDS * 1000);
        db.run('DELETE FROM findings WHERE timestamp < ?', [cutoffTime], function(err) {
            if (err) {
                console.error('❌ Cleanup failed:', err.message);
            } else if (this.changes > 0) {
                console.log(`🧹 Cleaned up ${this.changes} old findings (>${RETENTION_SECONDS}s)`);
            }
        });
    }, CLEANUP_INTERVAL * 1000);
});

// ========================================
// HELPER FUNCTIONS
// ========================================

function validateFinding(data) {
    if (!data.jobId || typeof data.jobId !== 'string') {
        return { valid: false, error: 'Invalid or missing jobId' };
    }
    if (!data.placeId || typeof data.placeId !== 'string') {
        return { valid: false, error: 'Invalid or missing placeId' };
    }
    if (!data.pets || !Array.isArray(data.pets) || data.pets.length === 0) {
        return { valid: false, error: 'Invalid or empty pets array' };
    }
    
    const sanitizedPets = data.pets.filter(pet => 
        typeof pet === 'string' && pet.length > 0 && pet.length < 200
    );
    
    if (sanitizedPets.length === 0) {
        return { valid: false, error: 'No valid pets after sanitization' };
    }
    
    return { valid: true, sanitizedPets };
}

// ========================================
// API ENDPOINTS
// ========================================

app.get('/health', (req, res) => {
    db.get('SELECT COUNT(*) as count FROM findings', (err, row) => {
        res.json({ 
            status: 'ok', 
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            timestamp: Date.now(),
            activefindings: row ? row.count : 0,
            retentionSeconds: RETENTION_SECONDS
        });
    });
});

app.post('/api/submit', submitLimiter, async (req, res) => {
    try {
        const validation = validateFinding(req.body);
        
        if (!validation.valid) {
            return res.status(400).json({ 
                success: false, 
                error: validation.error 
            });
        }

        const { jobId, placeId, rates } = req.body;
        const pets = validation.sanitizedPets;
        const timestamp = Date.now();

        const petsJson = JSON.stringify(pets);
        const ratesJson = rates ? JSON.stringify(rates) : null;

        db.run(
            `INSERT INTO findings (jobId, placeId, pets, rates, timestamp) 
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(jobId, placeId) 
             DO UPDATE SET 
                pets = excluded.pets,
                rates = excluded.rates,
                timestamp = excluded.timestamp`,
            [jobId, placeId, petsJson, ratesJson, timestamp],
            function(err) {
                if (err) {
                    console.error('❌ Database insert failed:', err.message);
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Database error' 
                    });
                }

                console.log(`✅ ${pets.length} pets | Server: ${jobId.substring(0, 8)}...`);
                
                res.json({ 
                    success: true, 
                    message: 'Finding stored',
                    id: this.lastID,
                    timestamp,
                    expiresIn: RETENTION_SECONDS
                });
            }
        );

    } catch (error) {
        console.error('❌ Submit error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

app.get('/api/pets', queryLimiter, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const minTimestamp = parseInt(req.query.minTimestamp) || 0;

        db.all(
            `SELECT jobId, placeId, pets, rates, timestamp 
             FROM findings 
             WHERE timestamp >= ?
             ORDER BY timestamp DESC 
             LIMIT ?`,
            [minTimestamp, Math.min(limit, 500)],
            (err, rows) => {
                if (err) {
                    console.error('❌ Database query failed:', err.message);
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Database error' 
                    });
                }

                const findings = rows.map(row => ({
                    jobId: row.jobId,
                    placeId: row.placeId,
                    pets: JSON.parse(row.pets),
                    rates: row.rates ? JSON.parse(row.rates) : null,
                    timestamp: row.timestamp
                }));

                res.json({ 
                    success: true, 
                    pets: findings,
                    count: findings.length
                });
            }
        );

    } catch (error) {
        console.error('❌ Query error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

app.get('/api/stats', (req, res) => {
    db.get('SELECT COUNT(*) as total FROM findings', (err, row) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        res.json({
            success: true,
            totalFindings: row.total,
            retentionSeconds: RETENTION_SECONDS,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage(),
            timestamp: Date.now()
        });
    });
});

app.delete('/api/clear', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey !== process.env.ADMIN_API_KEY && apiKey !== 'your-secret-key-here') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }

    db.run('DELETE FROM findings', (err) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        console.log('🗑️ All findings cleared');
        res.json({ success: true, message: 'All findings cleared' });
    });
});

// ========================================
// ERROR HANDLING
// ========================================

app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found' 
    });
});

app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// ========================================
// SERVER STARTUP
// ========================================

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('========================================');
    console.log('🚀 SWIFT NOTIFIER - ULTRA FAST MODE');
    console.log('========================================');
    console.log(`📡 Port: ${PORT}`);
    console.log(`💾 Database: ${DB_PATH}`);
    console.log(`⏱️  Retention: ${RETENTION_SECONDS} seconds`);
    console.log(`🧹 Cleanup: Every ${CLEANUP_INTERVAL} seconds`);
    console.log(`⚡ Rate Limits: 100/sec submit, 200/100ms query`);
    console.log('========================================');
    console.log('');
});

process.on('SIGTERM', () => {
    console.log('📴 Shutting down gracefully...');
    server.close(() => {
        db.close((err) => {
            if (err) console.error('❌ Error closing database:', err.message);
            else console.log('✅ Database connection closed');
            process.exit(0);
        });
    });
});

process.on('SIGINT', () => {
    console.log('📴 Shutting down gracefully...');
    server.close(() => {
        db.close((err) => {
            if (err) console.error('❌ Error closing database:', err.message);
            else console.log('✅ Database connection closed');
            process.exit(0);
        });
    });
});

module.exports = app;
