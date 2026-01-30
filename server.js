const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { Telegraf } = require('telegraf');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = '8324155535:AAEMBsrTT51QheDgCM8HKEBB9JsF7fsB8rE';
const BOT_USERNAME = 'bbgdpsauth11bot';

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(__dirname));

// --- DATABASE ---
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));

function loadDB() {
    if (!fs.existsSync(DB_FILE)) return { levels: [], list: [], pending: [] };
    return JSON.parse(fs.readFileSync(DB_FILE));
}

function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return {};
    return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(data) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

function logAudit(action, user) {
    console.log(`[AUDIT] ${user}: ${action}`);
    // In a real app, append to a file
}

// --- TELEGRAM BOT ---
const bot = new Telegraf(BOT_TOKEN);

// User mapping: username -> chat_id
// Stored in users.json: { "username": { chatId: 123, role: 'user'|'admin', banned: false } }

bot.start((ctx) => {
    const user = ctx.from;
    const users = loadUsers();

    if (!user.username) return ctx.reply("Please set a Telegram username to use this bot.");

    const username = user.username.toLowerCase();

    if (!users[username]) {
        users[username] = { chatId: ctx.chat.id, role: 'user', banned: false, tgId: user.id };
        saveUsers(users);
        ctx.reply(`Welcome, @${user.username}! You are registered as a User.`);
    } else {
        // Update chat ID if changed
        users[username].chatId = ctx.chat.id;
        users[username].tgId = user.id;
        saveUsers(users);
        ctx.reply(`Welcome back, @${user.username}!`);
    }
});

// COMMANDS
bot.command('promote', (ctx) => {
    // Only allow if sender is already admin or "Owner" (hardcoded for safety if DB is empty)
    const sender = ctx.from.username?.toLowerCase();
    const users = loadUsers();

    // Safety: First user is owner if no admins exist, or check specific ID
    // For now, let's assume the bot owner or first user can promote.
    // Simplifying: checking if sender is admin or there are NO admins yet.
    const hasAdmins = Object.values(users).some(u => u.role === 'admin');

    if (hasAdmins && users[sender]?.role !== 'admin') {
        return ctx.reply("You do not have permission.");
    }

    const targetUser = ctx.message.text.split(' ')[1];
    if (!targetUser || !targetUser.startsWith('@')) return ctx.reply("Usage: /promote @username");

    const targetName = targetUser.substring(1).toLowerCase();

    if (!users[targetName]) return ctx.reply("User not found. They must start the bot first.");

    users[targetName].role = 'admin';
    saveUsers(users);
    ctx.reply(`Promoted @${targetName} to Admin.`);

    bot.telegram.sendMessage(users[targetName].chatId, "You have been promoted to Admin!");
});

bot.command('demote', (ctx) => {
    const sender = ctx.from.username?.toLowerCase();
    const users = loadUsers();
    if (users[sender]?.role !== 'admin') return ctx.reply("No permission.");

    const targetUser = ctx.message.text.split(' ')[1];
    if (!targetUser || !targetUser.startsWith('@')) return ctx.reply("Usage: /demote @username");
    const targetName = targetUser.substring(1).toLowerCase();

    if (!users[targetName]) return ctx.reply("User not found.");

    users[targetName].role = 'user';
    saveUsers(users);
    ctx.reply(`Demoted @${targetName} to User.`);
});

bot.command('ban', (ctx) => {
    const sender = ctx.from.username?.toLowerCase();
    const users = loadUsers();
    if (users[sender]?.role !== 'admin') return ctx.reply("No permission.");

    const targetUser = ctx.message.text.split(' ')[1];
    if (!targetUser || !targetUser.startsWith('@')) return ctx.reply("Usage: /ban @username");
    const targetName = targetUser.substring(1).toLowerCase();

    if (!users[targetName]) return ctx.reply("User not found.");

    users[targetName].banned = true;
    saveUsers(users);
    ctx.reply(`Banned @${targetName}.`);
});

bot.launch();

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

// --- API ---

// AUTH MIDDLEWARE
function checkAuth(req, res, next) {
    const token = req.cookies['session_token'];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    // Simple logic: token is just username for now (in production use JWT)
    // To make it slightly secure without JWT lib dependency hell for this simple task:
    // We already verify hash on login.

    // Let's use signed cookies or just trust the cookie for this prototype since we verified hash.
    // For better security, creating a simple session map in memory.
    if (!SESSIONS[token]) return res.status(401).json({ error: 'Invalid session' });

    req.user = SESSIONS[token];
    next();
}

function checkAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
}

const SESSIONS = {}; // token -> user object

// TELEGRAM AUTH CHECK
app.get('/api/auth/telegram', (req, res) => {
    // Validate hash from query params
    const auth_data = req.query;
    const check_hash = auth_data.hash;
    const data_check_arr = [];

    for (let key in auth_data) {
        if (key !== 'hash') {
            data_check_arr.push(key + '=' + auth_data[key]);
        }
    }
    data_check_arr.sort();
    const data_check_string = data_check_arr.join('\n');

    const secret_key = crypto.createHash('sha256').update(BOT_TOKEN).digest();
    const hash = crypto.createHmac('sha256', secret_key).update(data_check_string).digest('hex');

    if (hash !== check_hash) {
        return res.status(403).json({ error: 'Data is NOT from Telegram' });
    }

    // Auth success
    const username = auth_data.username.toLowerCase();
    const users = loadUsers();

    // Check if banned
    if (users[username] && users[username].banned) return res.status(403).json({ error: 'You are banned.' });

    // Auto-register if not exists (via widget, entered without bot command first)
    if (!users[username]) {
        users[username] = { role: 'user', banned: false, tgId: auth_data.id };
        saveUsers(users);
    }

    // Create Session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    SESSIONS[sessionToken] = { username: username, role: users[username].role };

    // Set Cookie
    res.cookie('session_token', sessionToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 1 day

    // Notify Admin Channel (Console for now)
    console.log(`User Logged in: ${username}`);
    bot.telegram.sendMessage(users[username].chatId || auth_data.id, "New login detected via Web.");

    res.json({ success: true, user: SESSIONS[sessionToken] });
});



app.get('/api/me', checkAuth, (req, res) => {
    res.json(req.user);
});

app.get('/api/levels', (req, res) => {
    const db = loadDB();
    res.json(db.levels || []);
});

app.get('/api/users', (req, res) => {
    const users = loadUsers();
    // Return relevant user data for profile viewing
    res.json(users);
});

// ADMIN API
app.post('/api/admin/levels', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    db.levels.push(req.body);
    saveDB(db);
    logAudit(`${req.user.username} added level ${req.body.name}`, req.user.username);
    res.json({ success: true });
});

app.put('/api/admin/levels/:id', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    const idx = db.levels.findIndex(l => l.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });

    db.levels[idx] = { ...db.levels[idx], ...req.body };
    saveDB(db);
    logAudit(`${req.user.username} edited level ${db.levels[idx].name}`, req.user.username);
    res.json({ success: true });
});

app.delete('/api/admin/levels/:id', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    db.levels = db.levels.filter(l => l.id != req.params.id);
    saveDB(db);
    logAudit(`${req.user.username} deleted level ${req.params.id}`, req.user.username);
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
