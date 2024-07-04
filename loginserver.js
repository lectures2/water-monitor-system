const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const sqlite3 = require('sqlite3').verbose(); // Import SQLite module
const net = require('net');
const os = require('os');
const http = require('http');
const WebSocket = require('ws');

const app = express();

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Express session middleware
app.use(session({
secret: 'secret',
resave: true,
saveUninitialized: true
}));

// SQLite database connection
const db = new sqlite3.Database('users.db');

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
email TEXT,
password TEXT,
is_verified INTEGER DEFAULT 0
)`);

db.run(`CREATE TABLE IF NOT EXISTS notifications (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
message TEXT,
is_read INTEGER DEFAULT 0,
FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// Function to get the local IP address of the server
function getLocalIpAddress() {
const interfaces = os.networkInterfaces();
for (const interfaceName in interfaces) {
const interface = interfaces[interfaceName];
for (const { address, family, internal } of interface) {
if (family === 'IPv4' && !internal) {
return address;
}
}
}
return '127.0.0.1'; // Default to loopback address if no external IP found
}

// Create a TCP server
const tcpServer = net.createServer((socket) => {
// Handle incoming connections
console.log('Arduino connected.');

// Listen for data from the Arduino
socket.on('data', (data) => {
console.log('Data received from Arduino:', data.toString());
// Forward the data to all connected WebSocket clients
wss.clients.forEach((client) => {
if (client.readyState === WebSocket.OPEN) {
client.send(data.toString());
}
});
});

// Listen for Arduino disconnection
socket.on('end', () => {
console.log('Arduino disconnected.');
});

// Handle errors
socket.on('error', (err) => {
console.error('Socket error:', err.message);
});
});

// Listen on port 3360 for the TCP server
const tcpPort = 3360;
const ipAddress = getLocalIpAddress();
tcpServer.listen(tcpPort, ipAddress, () => {
console.log(`TCP Server listening on ${ipAddress}:${tcpPort}`);
});

// Attach WebSocket server to the HTTP server
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Handle WebSocket connections
wss.on('connection', (ws) => {
console.log('WebSocket Client connected.');

// Listen for messages from WebSocket clients (if needed)
ws.on('message', (message) => {
console.log('WebSocket Message received:', message);
});

// Listen for WebSocket client disconnection
ws.on('close', () => {
console.log('WebSocket Client disconnected.');
});

// Handle errors (if needed)
ws.on('error', (err) => {
console.error('WebSocket error:', err.message);
});
});

// Serve static files (HTML, CSS, JavaScript)
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/noti.html', (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'noti.html'));
});


app.get('/admin', (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'adminlogin.html'));
});

app.get('/signup', (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signup', async (req, res) => {
const { username, password } = req.body;

// Check if username already exists
db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}
if (row) {
return res.status(400).send('<script>alert("Username already exists"); window.location.href="/signup";</script>');
}

// Hash the password
const hashedPassword = await bcrypt.hash(password, 10);

// Insert user into the database
db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
if (err) {
return res.status(500).json({ message: 'Failed to create user' });
}
res.redirect('/');
});
});
});

app.post('/login', async (req, res) => {
const { username, password } = req.body;

// Retrieve user from the database
db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}
if (!row) {
req.session.errorMessage = 'Invalid username or password'; // Set error message
return res.redirect('/'); // Redirect to login page
}

// Compare passwords
const isValidPassword = await bcrypt.compare(password, row.password);
if (!isValidPassword) {
req.session.errorMessage = 'Invalid username or password'; // Set error message
return res.redirect('/'); // Redirect to login page
}

req.session.user = row; // Store user data in session
res.redirect('/logged-in');
});
});

app.get('/notifications', (req, res) => {
if (!req.session.user) {
return res.status(401).json({ message: 'Unauthorized' });
}

const userId = req.session.user.id;

// Fetch notifications for the logged-in user
db.all('SELECT * FROM notifications WHERE user_id = ? AND is_read = 0', [userId], (err, rows) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}

// Send the notifications as JSON response
res.json({ notifications: rows.map(row => row.message) });
});
});


// Route handler to get all users
app.get('/users', (req, res) => {
// Query the database to get all users
db.all('SELECT * FROM users', (err, rows) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}
// Send the list of users as JSON response
res.json(rows);
});
});

// Route handler to delete a user by ID
app.delete('/users/:id', (req, res) => {
const userId = req.params.id;

// Delete the user from the database
db.run('DELETE FROM users WHERE id = ?', userId, (err) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}
// Send success response
res.json({ message: 'User deleted successfully' });
});
});

// Route handler for logging out
app.post('/logout', (req, res) => {
// Destroy the session
req.session.destroy((err) => {
if (err) {
console.error('Error destroying session:', err);
return res.status(500).json({ message: 'Internal server error' });
}
// Redirect to the login page after logout
res.redirect('/');
});
});


// Route handler for admin login
app.post('/admin/login', async (req, res) => {
const { username, specialCode } = req.body;

// Check if the username and special code match the admin credentials
if (username === 'admin' && specialCode === '1234567890') {
// Redirect to the admin dashboard route
return res.redirect('/admindash.html');
} else {
// If the credentials don't match, redirect back to the admin login page with an error message
return res.status(401).send('<script>alert("Invalid username or special code"); window.location.href="/admin";</script>');
}
});

app.post('/admin/verify/:id', async (req, res) => {
const userId = req.params.id;

// Update the user record in the database to mark as verified
db.run('UPDATE users SET is_verified = 1 WHERE id = ?', userId, async (err) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}

// Retrieve the user's username
db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
if (err || !row) {
return res.status(500).json({ message: 'Database error' });
}

const notificationMessage = `Your account has been verified by the admin`;

// Save the notification in the database
db.run('INSERT INTO notifications (user_id, message) VALUES (?, ?)', [userId, notificationMessage], (err) => {
if (err) {
return res.status(500).json({ message: 'Database error' });
}

// Send a notification to all connected WebSocket clients
wss.clients.forEach((client) => {
if (client.readyState === WebSocket.OPEN) {
client.send(notificationMessage);
}
});
// Send success response
res.json({ message: 'User verified and notification sent successfully' });


// Redirect back to the admin dashboard
res.redirect('/admin-dashboard');
});
});
});
});




app.get('/logged-in', (req, res) => {
if (!req.session.user) {
return res.redirect('/login');
}

res.render('logged-in', { username: req.session.user.username });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
