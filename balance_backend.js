const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware
app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'balance_study.db');
const db = new sqlite3.Database(dbPath);

// Create tables if they don't exist
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        age INTEGER NOT NULL,
        gender TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Exercise entries table
    db.run(`CREATE TABLE IF NOT EXISTS exercise_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        left_leg_duration REAL NOT NULL,
        right_leg_duration REAL NOT NULL,
        comments TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )`);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Register endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { userId, age, gender, password } = req.body;

        if (!userId || !age || !gender || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert user into database
        db.run(
            'INSERT INTO users (user_id, age, gender, password_hash) VALUES (?, ?, ?, ?)',
            [userId, age, gender, passwordHash],
            function(err) {
                if (err) {
                    if (err.code === 'SQLITE_CONSTRAINT') {
                        return res.status(409).json({ error: 'User ID already exists' });
                    }
                    console.error('Registration error:', err);
                    return res.status(500).json({ error: 'Registration failed' });
                }

                console.log(`New user registered: ${userId}`);
                res.json({ success: true, userId: userId });
            }
        );
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { userId, password } = req.body;

        if (!userId || !password) {
            return res.status(400).json({ error: 'User ID and password are required' });
        }

        // Find user in database
        db.get(
            'SELECT user_id, password_hash FROM users WHERE user_id = ?',
            [userId],
            async (err, row) => {
                if (err) {
                    console.error('Login query error:', err);
                    return res.status(500).json({ error: 'Login failed' });
                }

                if (!row) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Verify password
                const passwordMatch = await bcrypt.compare(password, row.password_hash);
                if (!passwordMatch) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Generate JWT token
                const token = jwt.sign(
                    { userId: row.user_id },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                console.log(`User logged in: ${userId}`);
                res.json({
                    success: true,
                    userId: row.user_id,
                    token: token
                });
            }
        );
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Submit exercise entry
app.post('/api/entries', authenticateToken, (req, res) => {
    try {
        const { date, time, timestamp, leftLegDuration, rightLegDuration, comments } = req.body;
        const userId = req.user.userId;

        if (!date || !time || !timestamp || leftLegDuration === undefined || rightLegDuration === undefined) {
            return res.status(400).json({ error: 'Required fields missing' });
        }

        // Check if user has already submitted maximum entries for today (optional limit)
        const today = new Date().toISOString().split('T')[0];
        const MAX_DAILY_ENTRIES = 10; // Adjust as needed

        db.get(
            'SELECT COUNT(*) as count FROM exercise_entries WHERE user_id = ? AND date = ?',
            [userId, today],
            (err, row) => {
                if (err) {
                    console.error('Entry count query error:', err);
                    return res.status(500).json({ error: 'Failed to check entry limit' });
                }

                if (row.count >= MAX_DAILY_ENTRIES) {
                    return res.status(429).json({ error: 'Daily entry limit reached' });
                }

                // Insert exercise entry
                db.run(
                    `INSERT INTO exercise_entries 
                     (user_id, date, time, timestamp, left_leg_duration, right_leg_duration, comments) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [userId, date, time, timestamp, leftLegDuration, rightLegDuration, comments || ''],
                    function(err) {
                        if (err) {
                            console.error('Entry insertion error:', err);
                            return res.status(500).json({ error: 'Failed to save entry' });
                        }

                        console.log(`New entry saved for user: ${userId}`);
                        res.json({ success: true, entryId: this.lastID });
                    }
                );
            }
        );
    } catch (error) {
        console.error('Entry submission error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user statistics
app.get('/api/user-stats/:userId', authenticateToken, (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Verify user is requesting their own stats
        if (userId !== req.user.userId) {
            return res.status(403).json({ error: 'Access forbidden' });
        }

        const today = new Date().toISOString().split('T')[0];

        // Get today's count
        db.get(
            'SELECT COUNT(*) as todayCount FROM exercise_entries WHERE user_id = ? AND date = ?',
            [userId, today],
            (err, todayResult) => {
                if (err) {
                    console.error('Today count query error:', err);
                    return res.status(500).json({ error: 'Failed to get statistics' });
                }

                // Get total count
                db.get(
                    'SELECT COUNT(*) as totalCount FROM exercise_entries WHERE user_id = ?',
                    [userId],
                    (err, totalResult) => {
                        if (err) {
                            console.error('Total count query error:', err);
                            return res.status(500).json({ error: 'Failed to get statistics' });
                        }

                        // Get unique study days
                        db.get(
                            'SELECT COUNT(DISTINCT date) as studyDays FROM exercise_entries WHERE user_id = ?',
                            [userId],
                            (err, daysResult) => {
                                if (err) {
                                    console.error('Study days query error:', err);
                                    return res.status(500).json({ error: 'Failed to get statistics' });
                                }

                                // Get today's entries
                                db.all(
                                    `SELECT time, left_leg_duration, right_leg_duration, comments 
                                     FROM exercise_entries 
                                     WHERE user_id = ? AND date = ? 
                                     ORDER BY timestamp DESC`,
                                    [userId, today],
                                    (err, todayEntries) => {
                                        if (err) {
                                            console.error('Today entries query error:', err);
                                            return res.status(500).json({ error: 'Failed to get today\'s entries' });
                                        }

                                        res.json({
                                            todayCount: todayResult.todayCount,
                                            totalCount: totalResult.totalCount,
                                            studyDays: daysResult.studyDays,
                                            todayEntries: todayEntries.map(entry => ({
                                                time: entry.time,
                                                leftLegDuration: entry.left_leg_duration,
                                                rightLegDuration: entry.right_leg_duration,
                                                comments: entry.comments
                                            }))
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    } catch (error) {
        console.error('Stats retrieval error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Export data endpoint (for researchers)
app.get('/api/export', (req, res) => {
    try {
        const adminKey = req.headers['x-admin-key'];
        if (adminKey !== process.env.ADMIN_KEY) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        db.all(
            `SELECT 
                u.user_id, u.age, u.gender, u.created_at as user_created,
                e.date, e.time, e.timestamp, e.left_leg_duration, e.right_leg_duration, e.comments
             FROM users u 
             LEFT JOIN exercise_entries e ON u.user_id = e.user_id
             ORDER BY u.user_id, e.timestamp`,
            (err, rows) => {
                if (err) {
                    console.error('Export query error:', err);
                    return res.status(500).json({ error: 'Export failed' });
                }

                res.json({
                    exportDate: new Date().toISOString(),
                    totalUsers: rows.filter(row => row.date === null).length,
                    totalEntries: rows.filter(row => row.date !== null).length,
                    data: rows
                });
            }
        );
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Balance Research Backend running on port ${PORT}`);
    console.log(`Database: ${dbPath}`);
    console.log('Available endpoints:');
    console.log('  GET  /api/health');
    console.log('  POST /api/register');
    console.log('  POST /api/login');
    console.log('  POST /api/entries');
    console.log('  GET  /api/user-stats/:userId');
    console.log('  GET  /api/export (admin only)');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});