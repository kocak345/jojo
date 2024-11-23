const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();

// Setup database
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Database error:', err);
    } else {
        db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)');
        db.run('CREATE TABLE IF NOT EXISTS subjects (id INTEGER PRIMARY KEY, name TEXT, teacher_id INTEGER)');
    }
});

// Setup Express
app.use(express.static('views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Setup file upload with multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({ storage: storage });

// Register route
app.post('/register', (req, res) => {
    const { username, password, role } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;
        db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], function (err) {
            if (err) {
                res.status(500).json({ error: err.message });
            } else {
                res.status(200).json({ message: 'User registered' });
            }
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) throw err;
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) throw err;
            if (match) {
                const token = jwt.sign({ id: user.id, role: user.role }, 'secret', { expiresIn: '1h' });
                res.json({ message: 'Login successful', token });
            } else {
                res.status(400).json({ message: 'Invalid password' });
            }
        });
    });
});

// Upload PowerPoint route (for teacher)
app.post('/upload', upload.single('ppt'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }
    res.status(200).json({ message: 'File uploaded successfully', file: req.file });
});

// Dashboard for teachers (view uploaded PowerPoint files)
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// Serve the main page (login page)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Set the server port
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
