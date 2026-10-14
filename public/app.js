(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const authView = $('authView');
  const appView = $('appView');
  const authForm = $('authForm');
  const authError = $('authError');
  const usernameInput = $('usernameInput');
  const passwordInput = $('passwordInput');
  const authSubmit = $('authSubmit');
  const loginTab = $('loginTab');
  const registerTab = $('registerTab');
  const messageArea = $('messageArea');
  const userList = $('userList');
  const chatList = $('chatList');
  const messageForm = $('messageForm');
  const messageInput = $('messageInput');
  const charCount = $('charCount');
  const toastElement = $('toast');
  const connectionNote = $('connectionNote');

  let authMode = 'login';
  let me = null;
  let currentChat = { type: 'global', username: null };
  let currentMessages = new Set();
  let eventStream = null;
  let toastTimer = null;
  const unread = new Set();

  function escapeKey(value) { return String(value).toLowerCase(); }
  function getCurrentChatKey() {
    if (currentChat.type === 'global') return 'global';
    return `dm:${[escapeKey(me.username), escapeKey(currentChat.username)].sort().join(':')}`;
  }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
    let data = {};
    try { data = await response.json(); } catch { /* Keep an empty result for unexpected responses. */ }
    if (!response.ok) {
      const error = new Error(data.error || `Ошибка ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function showToast(message) {
    toastElement.textContent = message;
    toastElement.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastElement.classList.remove('show'), 2600);
  }

  function applyTheme(theme) {
    const selected = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = selected;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = selected === 'dark' ? '#151311' : '#f7f4f0';
    $('themeIcon').textContent = selected === 'dark' ? '☼' : '☾';
    $('themeToggle').title = selected === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему';
    try { localStorage.setItem('atlicks-theme', selected); } catch { /* Theme still works for this page. */ }
  }

  function loadTheme() {
    let saved = 'dark';
    try { saved = localStorage.getItem('atlicks-theme') || 'dark'; } catch { /* Use dark theme by default. */ }
    applyTheme(saved);
  }

  function setAuthMode(mode) {
    authMode = mode;
    loginTab.classList.toggle('active', mode === 'login');
    registerTab.classList.toggle('active', mode === 'register');
    authSubmit.textContent = mode === 'login' ? 'Войти' : 'Создать аккаунт';
    passwordInput.autocomplete = mode === 'login' ? 'current-password' : 'new-password';
    authError.textContent = '';
  }

  function showAuth() {
    appView.classList.add('hidden');
    authView.classList.remove('hidden');
    usernameInput.focus();
  }

  function showApp(user) {
    me = user;
    authView.classList.add('hidden');
    appView.classList.remove('hidden');
    $('myName').textContent = user.username;
    $('myAvatar').textContent = user.username.slice(0, 1).toUpperCase();
    currentChat = { type: 'global', username: null };
    currentMessages = new Set();
    drawSelectedChat();
    loadChat().catch((error) => showToast(error.message));
    refreshUsers();
    connectSocket();
  }

  function disconnectSocket() {
    if (eventStream) {
      const old = eventStream;
      eventStream = null;
      old.close();
    }
  }

  function connectSocket() {
    if (!me || eventStream) return;
    const stream = new EventSource('/api/events');
    let connectedOnce = false;
    eventStream = stream;
    stream.addEventListener('open', () => {
      if (eventStream === stream) connectionNote.classList.add('hidden');
      if (connectedOnce) loadChat().catch((error) => showToast(error.message));
      connectedOnce = true;
    });
    stream.addEventListener('message', (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
      if (data.type === 'presence') {
        updatePresence(data.username, data.online);
        return;
      }
      if (data.type === 'message' && data.message) {
        if (data.chatKey === getCurrentChatKey()) {
          appendMessage(data.message);
          unread.delete(data.chatKey);
        } else if (data.message.from !== me.username) {
          unread.add(data.chatKey);
          updateUserUnread(data.chatKey);
        }
        return;
      }
      if (data.type === 'expired' && data.chatKey === getCurrentChatKey() && Array.isArray(data.ids)) {
        for (const id of data.ids) {
          currentMessages.delete(id);
          const node = messageArea.querySelector(`[data-message-id="${CSS.escape(id)}"]`);
          if (node) node.remove();
        }
        if (messageArea.querySelectorAll('.message').length === 0) showEmptyState();
      }
    });
    stream.addEventListener('error', () => {
      if (eventStream === stream) connectionNote.classList.remove('hidden');
    });
  }

  function showEmptyState() {
    if (messageArea.querySelector('.empty-state')) return;
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    const symbol = document.createElement('span');
    symbol.className = 'empty-symbol';
    symbol.textContent = '↗';
    const title = document.createElement('strong');
    title.textContent = 'Начни общение';
    const p = document.createElement('p');
    p.textContent = 'Сообщения исчезают через час — история не сохраняется.';
    empty.append(symbol, title, p);
    messageArea.replaceChildren(empty);
  }

  function formatTime(timestamp) {
    try { return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date(timestamp)); }
    catch { return ''; }
  }

  function appendMessage(message) {
    if (!message || currentMessages.has(message.id)) return;
    currentMessages.add(message.id);
    const empty = messageArea.querySelector('.empty-state');
    if (empty) empty.remove();
    const node = document.createElement('article');
    node.className = `message${escapeKey(message.from) === escapeKey(me.username) ? ' own' : ''}`;
    node.dataset.messageId = message.id;
    const meta = document.createElement('div');
    meta.className = 'message-meta';
    if (escapeKey(message.from) !== escapeKey(me.username)) {
      const author = document.createElement('span');
      author.className = 'message-author';
      author.textContent = message.from;
      meta.append(author);
    } else {
      const author = document.createElement('span');
      author.className = 'message-author';
      author.textContent = 'Вы';
      meta.append(author);
    }
    const time = document.createElement('time');
    time.textContent = formatTime(message.createdAt);
    time.dateTime = new Date(message.createdAt).toISOString();
    meta.append(time);
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    bubble.textContent = message.text;
    node.append(meta, bubble);
    messageArea.append(node);
    messageArea.scrollTop = messageArea.scrollHeight;
  }

  async function loadChat() {
    messageArea.replaceChildren();
    currentMessages = new Set();
    const params = currentChat.type === 'dm' ? `?with=${encodeURIComponent(currentChat.username)}` : '';
    const data = await api(`/api/messages${params}`);
    for (const message of data.messages) appendMessage(message);
    if (!data.messages.length) showEmptyState();
    unread.delete(getCurrentChatKey());
    drawSelectedChat();
  }

  function drawSelectedChat() {
    const isGlobal = currentChat.type === 'global';
    $('chatTitle').textContent = isGlobal ? 'Общий чат' : currentChat.username;
    $('chatSubtitle').textContent = isGlobal ? 'Сообщения для всех пользователей' : 'Личная переписка';
    $('chatAvatar').textContent = isGlobal ? '#' : (currentChat.username || '?').slice(0, 1).toUpperCase();
    $('chatAvatar').classList.toggle('group-avatar', isGlobal);
    $('chatAvatar').classList.toggle('user-avatar', !isGlobal);
    chatList.querySelectorAll('[data-chat="global"]').forEach((item) => item.classList.toggle('selected', isGlobal));
    userList.querySelectorAll('[data-username]').forEach((item) => {
      item.classList.toggle('selected', !isGlobal && escapeKey(item.dataset.username) === escapeKey(currentChat.username));
    });
  }

  async function selectChat(type, username = null) {
    currentChat = type === 'global' ? { type: 'global', username: null } : { type: 'dm', username };
    appView.classList.add('mobile-chat');
    drawSelectedChat();
    try { await loadChat(); }
    catch (error) { showToast(error.message); }
    messageInput.focus({ preventScroll: true });
  }

  async function refreshUsers() {
    if (!me) return;
    try {
      const data = await api('/api/users');
      userList.replaceChildren();
      if (!data.users.length) {
        const note = document.createElement('div');
        note.className = 'small-muted';
        note.textContent = 'Пока здесь только ты';
        userList.append(note);
        return;
      }
      for (const user of data.users) {
        const button = document.createElement('button');
        button.className = 'user-row';
        button.type = 'button';
        button.dataset.username = user.username;
        button.classList.toggle('selected', currentChat.type === 'dm' && escapeKey(currentChat.username) === escapeKey(user.username));
        const avatar = document.createElement('span');
        avatar.className = 'avatar user-avatar';
        avatar.textContent = user.username.slice(0, 1).toUpperCase();
        const copy = document.createElement('span');
        copy.className = 'user-copy';
        const name = document.createElement('strong');
        name.textContent = user.username;
        const status = document.createElement('small');
        status.textContent = user.online ? 'В сети' : 'Не в сети';
        copy.append(name, status);
        const dot = document.createElement('span');
        dot.className = `user-state${user.online ? ' online' : ''}`;
        button.append(avatar, copy, dot);
        button.addEventListener('click', () => selectChat('dm', user.username));
        userList.append(button);
      }
    } catch (error) {
      if (error.status === 401) logoutLocally();
    }
  }

  function updateUserUnread(chatKey) {
    if (!chatKey.startsWith('dm:')) return;
    const parts = chatKey.slice(3).split(':');
    const other = parts.find((part) => part !== escapeKey(me.username));
    const button = [...userList.querySelectorAll('[data-username]')].find((item) => escapeKey(item.dataset.username) === other);
    if (button) {
      const copy = button.querySelector('.user-copy small');
      if (copy) copy.textContent = 'Новое сообщение';
    }
  }

  function updatePresence(username, online) {
    if (!username || typeof online !== 'boolean') return;
    const button = [...userList.querySelectorAll('[data-username]')].find((item) => escapeKey(item.dataset.username) === escapeKey(username));
    if (!button) return;
    const chatKey = `dm:${[escapeKey(me.username), escapeKey(username)].sort().join(':')}`;
    const copy = button.querySelector('.user-copy small');
    const dot = button.querySelector('.user-state');
    if (copy && !unread.has(chatKey)) copy.textContent = online ? 'В сети' : 'Не в сети';
    if (dot) dot.classList.toggle('online', online);
  }

  async function logoutLocally() {
    me = null;
    disconnectSocket();
    appView.classList.add('hidden');
    authView.classList.remove('hidden');
    authForm.reset();
    setAuthMode('login');
  }

  authForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    authError.textContent = '';
    authSubmit.disabled = true;
    authSubmit.textContent = authMode === 'login' ? 'Входим…' : 'Создаём…';
    try {
      const data = await api(`/api/${authMode === 'login' ? 'login' : 'register'}`, {
        method: 'POST',
        body: JSON.stringify({ username: usernameInput.value.trim(), password: passwordInput.value })
      });
      passwordInput.value = '';
      showApp(data.user);
    } catch (error) {
      authError.textContent = error.message;
    } finally {
      authSubmit.disabled = false;
      authSubmit.textContent = authMode === 'login' ? 'Войти' : 'Создать аккаунт';
    }
  });
  loginTab.addEventListener('click', () => setAuthMode('login'));
  registerTab.addEventListener('click', () => setAuthMode('register'));
  $('themeToggle').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('logoutBtn').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST', body: '{}' }); } catch { /* Local logout is still available. */ }
    await logoutLocally();
  });
  $('backBtn').addEventListener('click', () => appView.classList.remove('mobile-chat'));
  chatList.querySelector('[data-chat="global"]').addEventListener('click', () => selectChat('global'));
  messageInput.addEventListener('input', () => { charCount.textContent = `${[...messageInput.value].length}/1000`; });
  messageForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !me) return;
    $('sendBtn').disabled = true;
    try {
      const payload = { text };
      if (currentChat.type === 'dm') payload.to = currentChat.username;
      const data = await api('/api/messages', { method: 'POST', body: JSON.stringify(payload) });
      appendMessage(data.message);
      messageInput.value = '';
      charCount.textContent = '0/1000';
      messageInput.focus();
    } catch (error) {
      showToast(error.message);
    } finally {
      $('sendBtn').disabled = false;
    }
  });

  async function boot() {
    loadTheme();
    try {
      const data = await api('/api/me');
      showApp(data.user);
    } catch {
      showAuth();
    }
  }

  window.addEventListener('pagehide', () => {
    if (eventStream) eventStream.close();
  });

  boot();
})();
