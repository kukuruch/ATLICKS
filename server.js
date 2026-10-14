import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const MESSAGE_TTL_MS = 60 * 60 * 1000;
const MAX_MESSAGE_LENGTH = 1000;
const MAX_MESSAGES_PER_CHAT = 1000;
const PBKDF2_ITERATIONS = 150_000;
const pbkdf2 = promisify(crypto.pbkdf2);

if (IS_PRODUCTION && !process.env.SESSION_SECRET) {
  console.warn('SESSION_SECRET is not set. Sessions will be invalidated whenever this process restarts.');
}

let users = [];
let saveQueue = Promise.resolve();
const messagesByChat = new Map();
const streams = new Set();
const authRate = new Map();
const messageRate = new Map();

function usernameKey(value) {
  return String(value).toLowerCase();
}

function validUsername(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9_]{3,20}$/.test(value);
}

function publicUser(user) {
  return { username: user.username };
}

async function loadUsers() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });
  try {
    const text = await fs.promises.readFile(USERS_FILE, 'utf8');
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) throw new Error('users.json must contain a JSON array');
    users = parsed.filter((u) => u && validUsername(u.username) && typeof u.salt === 'string' && typeof u.passwordHash === 'string');
  } catch (error) {
    if (error.code === 'ENOENT') {
      users = [];
      await fs.promises.writeFile(USERS_FILE, '[]\n', { mode: 0o600 });
    } else {
      console.error(`Could not read ${USERS_FILE}:`, error.message);
      throw error;
    }
  }
}

function saveUsers() {
  const serialized = `${JSON.stringify(users, null, 2)}\n`;
  saveQueue = saveQueue.then(async () => {
    await fs.promises.mkdir(DATA_DIR, { recursive: true });
    const temporaryPath = `${USERS_FILE}.tmp`;
    await fs.promises.writeFile(temporaryPath, serialized, { mode: 0o600 });
    await fs.promises.rename(temporaryPath, USERS_FILE);
  });
  return saveQueue;
}

function findUser(name) {
  const key = usernameKey(name);
  return users.find((user) => usernameKey(user.username) === key);
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function createSession(username) {
  const payload = Buffer.from(JSON.stringify({
    u: username,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
  })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readCookies(header = '') {
  const values = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0) values[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return values;
}

function getSessionUser(req) {
  const token = readCookies(req.headers.cookie).atlicks_session;
  if (!token || !token.includes('.')) return null;
  const [payload, signature] = token.split('.', 2);
  const expected = sign(payload);
  const left = Buffer.from(signature || '');
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.u || !Number.isFinite(data.exp) || data.exp < Date.now() / 1000) return null;
    return findUser(data.u) || null;
  } catch {
    return null;
  }
}

function sessionCookie(token, maxAge = SESSION_TTL_SECONDS) {
  return `atlicks_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAge}${IS_PRODUCTION ? '; Secure' : ''}`;
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
}

function sendJson(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(JSON.stringify(data));
}

async function readJson(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body, 'utf8') > 12 * 1024) {
      const error = new Error('Запрос слишком большой.');
      error.status = 413;
      throw error;
    }
  }
  try {
    return body ? JSON.parse(body) : {};
  } catch {
    const error = new Error('Некорректный JSON.');
    error.status = 400;
    throw error;
  }
}

function checkRateLimit(map, key, limit, windowMs) {
  const now = Date.now();
  let record = map.get(key);
  if (!record || now - record.start >= windowMs) {
    record = { start: now, count: 0 };
    map.set(key, record);
  }
  record.count += 1;
  return record.count <= limit;
}

function requestIp(req) {
  // Trust the platform's forwarded address only as an identifier for rate limiting.
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').toString().split(',')[0].trim().slice(0, 100);
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function chatKeyFor(userA, userB) {
  return `dm:${[usernameKey(userA), usernameKey(userB)].sort().join(':')}`;
}

function getChatKey(currentUser, otherUser) {
  if (!otherUser) return 'global';
  const recipient = findUser(otherUser);
  if (!recipient) return null;
  if (usernameKey(recipient.username) === usernameKey(currentUser.username)) return null;
  return chatKeyFor(currentUser.username, recipient.username);
}

function sendStream(stream, payload) {
  if (!stream.closed && !stream.res.destroyed && !stream.res.writableEnded) {
    stream.res.write(`data: ${JSON.stringify(payload)}\n\n`);
  }
}

function notifyPresence(username, online) {
  for (const stream of streams) sendStream(stream, { type: 'presence', username, online });
}

function emitMessage(chatKey, message) {
  for (const stream of streams) {
    if (chatKey === 'global') {
      sendStream(stream, { type: 'message', chatKey, message });
      continue;
    }
    const parts = chatKey.slice(3).split(':');
    if (parts.includes(usernameKey(stream.username))) sendStream(stream, { type: 'message', chatKey, message });
  }
}

function emitExpired(chatKey, ids) {
  for (const stream of streams) {
    if (chatKey === 'global') {
      sendStream(stream, { type: 'expired', chatKey, ids });
    } else {
      const parts = chatKey.slice(3).split(':');
      if (parts.includes(usernameKey(stream.username))) sendStream(stream, { type: 'expired', chatKey, ids });
    }
  }
}

function startEventStream(req, res, user) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write('retry: 2500\n\n');
  const wasOnline = [...streams].some((item) => usernameKey(item.username) === usernameKey(user.username));
  const stream = { res, username: user.username, closed: false };
  streams.add(stream);
  const heartbeat = setInterval(() => {
    if (stream.closed || res.destroyed || res.writableEnded) return;
    res.write(': keep-alive\n\n');
  }, 25_000);
  heartbeat.unref();
  sendStream(stream, { type: 'ready' });
  if (!wasOnline) notifyPresence(user.username, true);
  res.on('close', () => {
    if (stream.closed) return;
    stream.closed = true;
    clearInterval(heartbeat);
    streams.delete(stream);
    const stillOnline = [...streams].some((item) => usernameKey(item.username) === usernameKey(stream.username));
    if (!stillOnline) notifyPresence(stream.username, false);
  });
}

function cleanExpiredMessages() {
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  for (const [chatKey, list] of messagesByChat.entries()) {
    const expired = [];
    const kept = [];
    for (const message of list) {
      if (message.createdAt < cutoff) expired.push(message.id);
      else kept.push(message);
    }
    if (expired.length) emitExpired(chatKey, expired);
    if (kept.length) messagesByChat.set(chatKey, kept);
    else messagesByChat.delete(chatKey);
  }
}

function handleApiError(res, error) {
  if (error.status) {
    sendJson(res, error.status, { error: error.message });
  } else {
    console.error(error);
    sendJson(res, 500, { error: 'Внутренняя ошибка сервера.' });
  }
}

async function routeApi(req, res, url) {
  if (req.method === 'GET' && url.pathname === '/health') {
    return sendJson(res, 200, { ok: true });
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !sameOrigin(req)) {
    return sendJson(res, 403, { error: 'Запрос с другого сайта запрещён.' });
  }

  if (req.method === 'POST' && (url.pathname === '/api/register' || url.pathname === '/api/login')) {
    if (!checkRateLimit(authRate, requestIp(req), 15, 10 * 60 * 1000)) {
      return sendJson(res, 429, { error: 'Слишком много попыток. Попробуй позже.' });
    }
    const body = await readJson(req);
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!validUsername(username)) {
      return sendJson(res, 400, { error: 'Ник: 3–20 символов, только латинские буквы, цифры и _.' });
    }
    if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 256) {
      return sendJson(res, 400, { error: 'Пароль должен быть не короче 8 символов.' });
    }

    if (url.pathname === '/api/register') {
      if (findUser(username)) return sendJson(res, 409, { error: 'Этот ник уже занят.' });
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = (await pbkdf2(password, salt, PBKDF2_ITERATIONS, 32, 'sha256')).toString('hex');
      // Recheck after the asynchronous hash operation to avoid duplicate concurrent registrations.
      if (findUser(username)) return sendJson(res, 409, { error: 'Этот ник уже занят.' });
      const user = { username, salt, passwordHash: hash, createdAt: new Date().toISOString() };
      users.push(user);
      try {
        await saveUsers();
      } catch (error) {
        users = users.filter((item) => item !== user);
        console.error('Could not persist registration:', error.message);
        return sendJson(res, 507, { error: 'Не удалось сохранить аккаунт. Проверь постоянный диск Render.' });
      }
      return sendJson(res, 201, { user: publicUser(user) }, { 'Set-Cookie': sessionCookie(createSession(user.username)) });
    }

    const user = findUser(username);
    if (!user) return sendJson(res, 401, { error: 'Неверный ник или пароль.' });
    const hash = await pbkdf2(password, user.salt, PBKDF2_ITERATIONS, 32, 'sha256');
    const storedHash = Buffer.from(user.passwordHash, 'hex');
    if (storedHash.length !== hash.length || !crypto.timingSafeEqual(storedHash, hash)) {
      return sendJson(res, 401, { error: 'Неверный ник или пароль.' });
    }
    return sendJson(res, 200, { user: publicUser(user) }, { 'Set-Cookie': sessionCookie(createSession(user.username)) });
  }

  if (req.method === 'POST' && url.pathname === '/api/logout') {
    res.setHeader('Set-Cookie', sessionCookie('', 0));
    return sendJson(res, 200, { ok: true });
  }

  const currentUser = getSessionUser(req);
  if (!currentUser) return sendJson(res, 401, { error: 'Войди в аккаунт.' });

  if (req.method === 'GET' && url.pathname === '/api/me') {
    return sendJson(res, 200, { user: publicUser(currentUser) });
  }

  if (req.method === 'GET' && url.pathname === '/api/events') {
    startEventStream(req, res, currentUser);
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/users') {
    const result = users
      .filter((user) => usernameKey(user.username) !== usernameKey(currentUser.username))
      .map((user) => ({
        username: user.username,
        online: [...streams].some((stream) => usernameKey(stream.username) === usernameKey(user.username))
      }))
      .sort((a, b) => a.username.localeCompare(b.username));
    return sendJson(res, 200, { users: result });
  }

  if (req.method === 'GET' && url.pathname === '/api/messages') {
    const otherUser = url.searchParams.get('with') || '';
    const chatKey = getChatKey(currentUser, otherUser);
    if (!chatKey) return sendJson(res, 404, { error: 'Пользователь не найден.' });
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    const list = (messagesByChat.get(chatKey) || []).filter((message) => message.createdAt >= cutoff);
    return sendJson(res, 200, { messages: list });
  }

  if (req.method === 'POST' && url.pathname === '/api/messages') {
    const key = usernameKey(currentUser.username);
    if (!checkRateLimit(messageRate, key, 35, 60 * 1000)) {
      return sendJson(res, 429, { error: 'Слишком часто. Подожди немного.' });
    }
    const body = await readJson(req);
    const text = typeof body.text === 'string' ? body.text.trim() : '';
    const otherUser = typeof body.to === 'string' ? body.to.trim() : '';
    if (!text) return sendJson(res, 400, { error: 'Сообщение пустое.' });
    if ([...text].length > MAX_MESSAGE_LENGTH) return sendJson(res, 400, { error: `Максимум ${MAX_MESSAGE_LENGTH} символов.` });
    const chatKey = getChatKey(currentUser, otherUser);
    if (!chatKey) return sendJson(res, 404, { error: 'Получатель не найден.' });
    const message = {
      id: crypto.randomUUID(),
      from: currentUser.username,
      to: otherUser || null,
      text,
      createdAt: Date.now()
    };
    const list = messagesByChat.get(chatKey) || [];
    list.push(message);
    if (list.length > MAX_MESSAGES_PER_CHAT) list.splice(0, list.length - MAX_MESSAGES_PER_CHAT);
    messagesByChat.set(chatKey, list);
    emitMessage(chatKey, message);
    return sendJson(res, 201, { message });
  }

  return sendJson(res, 404, { error: 'Страница не найдена.' });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml'
};

async function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    return res.end('Method Not Allowed');
  }
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/') pathname = '/index.html';
  const allowed = new Set(['/index.html', '/style.css', '/app.js']);
  if (!allowed.has(pathname)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end('Not found');
  }
  const filePath = path.join(__dirname, 'public', pathname.slice(1));
  try {
    const content = await fs.promises.readFile(filePath);
    const canGzip = content.length > 1024 && /\bgzip\b/.test(req.headers['accept-encoding'] || '');
    const output = canGzip ? gzipSync(content, { level: 6 }) : content;
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[path.extname(filePath)] || 'application/octet-stream',
      'Cache-Control': pathname === '/index.html' ? 'no-cache' : 'public, max-age=3600',
      'Vary': 'Accept-Encoding',
      ...(canGzip ? { 'Content-Encoding': 'gzip' } : {}),
      'Content-Length': output.length
    });
    res.end(req.method === 'HEAD' ? undefined : output);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  }
}

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
    try {
      await routeApi(req, res, url);
    } catch (error) {
      handleApiError(res, error);
    }
    return;
  }
  await serveStatic(req, res, url);
});

// EventSource/SSE keeps updates lightweight and avoids a WebSocket dependency.
server.keepAliveTimeout = 75_000;
server.headersTimeout = 80_000;

setInterval(cleanExpiredMessages, 15_000).unref();
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of authRate) if (now - value.start > 15 * 60 * 1000) authRate.delete(key);
  for (const [key, value] of messageRate) if (now - value.start > 2 * 60 * 1000) messageRate.delete(key);
}, 60_000).unref();

loadUsers().then(() => {
  server.listen(PORT, '0.0.0.0', () => console.log(`ATLICKS is running on port ${PORT}; users file: ${USERS_FILE}`));
}).catch((error) => {
  console.error('Startup failed:', error);
  process.exit(1);
});
