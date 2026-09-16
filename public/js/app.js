import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  deriveMasterKey,
  deriveAuthVerifier,
  encryptPrivateKeyBackup,
  decryptPrivateKeyBackup,
  getSharedSecretKey,
  encryptMessage,
  decryptMessage,
  generateRandomBytes,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  clearSharedKeyCache,
  KeyStore,
  computeSafetyNumber,
  VerifiedKeys
} from './crypto.js';

import { API } from './api.js';
import { Realtime } from './socket.js';
import {
  isSoundEnabled,
  toggleSoundEnabled,
  playSentSound,
  playReceivedSound
} from './audio.js';
import {
  showToast,
  renderConversationItem,
  renderMessageBubble,
  renderTypingIndicator,
  removeTypingIndicator,
  renderDateDivider,
  formatDateDivider,
  scrollToBottom,
  escapeHtml,
  triggerHaptic,
  renderMessageSkeletons,
  renderConversationSkeletons
} from './ui.js';

// State
const state = {
  currentUser: null,
  localPrivateKey: null,
  localPublicKey: null,
  conversations: [],
  activeConversation: null,
  activeTargetUser: null,
  activeSharedKey: null,
  activeSafetyNumber: null,
  activeSafetyBlocks: [],
  activeFingerprint: null,
  activeContactVerified: false,
  activeKeyChanged: false,
  onlineUsers: new Set(),
  searchQuery: '',
  isTypingTimer: null,
  isTyping: false,
  unreadWhileScrolledCount: 0,
  lastSentText: '',
  drafts: {},
  unreadBackgroundCount: 0
};

// Elements
const elements = {
  appFavicon: document.getElementById('app-favicon'),
  searchShortcutBadge: document.getElementById('search-shortcut-badge'),
  soundToggleBtn: document.getElementById('sound-toggle-btn'),
  themeToggleBtn: document.getElementById('theme-toggle-btn'),
  themeColorMeta: document.getElementById('theme-color-meta'),
  newChatBtn: document.getElementById('new-chat-btn'),
  searchConvInput: document.getElementById('search-conv-input'),
  conversationsList: document.getElementById('conversations-list'),
  sidebarUsername: document.getElementById('sidebar-username'),
  sidebarAvatar: document.getElementById('sidebar-avatar'),
  logoutBtn: document.getElementById('logout-btn'),

  // Chat pane
  chatPane: document.getElementById('chat-pane'),
  emptyChatState: document.getElementById('empty-chat-state'),
  emptyChatStartBtn: document.getElementById('empty-chat-start-btn'),
  activeChatView: document.getElementById('active-chat-view'),
  chatHeaderAvatar: document.getElementById('chat-header-avatar'),
  chatHeaderName: document.getElementById('chat-header-name'),
  chatHeaderSubtitle: document.getElementById('chat-header-subtitle'),
  headerVerifiedBadge: document.getElementById('header-verified-badge'),
  btnVerifySafetyNumber: document.getElementById('btn-verify-safety-number'),
  messagesContainer: document.getElementById('messages-container'),
  scrollBottomBtn: document.getElementById('scroll-bottom-btn'),
  scrollBottomText: document.getElementById('scroll-bottom-text'),
  scrollBottomBadge: document.getElementById('scroll-bottom-badge'),
  composerInput: document.getElementById('composer-input'),
  sendBtn: document.getElementById('send-btn'),
  btnBack: document.getElementById('btn-back'),

  // Status banner
  connectionStatusBar: document.getElementById('connection-status-bar'),
  connectionStatusText: document.getElementById('connection-status-text'),

  // Auth modal
  authModal: document.getElementById('auth-modal'),
  authForm: document.getElementById('auth-form'),
  authTitle: document.getElementById('auth-title'),
  authSubtitle: document.getElementById('auth-subtitle'),
  authUsernameInput: document.getElementById('auth-username'),
  authPasswordInput: document.getElementById('auth-password'),
  authSubmitBtn: document.getElementById('auth-submit-btn'),
  authCryptoStatus: document.getElementById('auth-crypto-status'),
  tabLogin: document.getElementById('tab-login'),
  tabRegister: document.getElementById('tab-register'),

  // Search modal
  newChatModal: document.getElementById('new-chat-modal'),
  closeNewChatBtn: document.getElementById('close-new-chat-btn'),
  userSearchInput: document.getElementById('user-search-input'),
  searchResultsList: document.getElementById('search-results-list'),

  // Safety Number modal
  safetyNumberModal: document.getElementById('safety-number-modal'),
  closeSafetyModalBtn: document.getElementById('close-safety-modal-btn'),
  safetyRecipientName: document.getElementById('safety-recipient-name'),
  safetyAlertBanner: document.getElementById('safety-alert-banner'),
  safetyNumberGrid: document.getElementById('safety-number-grid'),
  safetyFingerprintDisplay: document.getElementById('safety-fingerprint-display'),
  btnCopySafetyNumber: document.getElementById('btn-copy-safety-number'),
  btnToggleVerifyContact: document.getElementById('btn-toggle-verify-contact')
};

let currentAuthMode = 'login';

// Initialize
async function initApp() {
  initTheme();
  updateSoundToggleButton();

  if (elements.searchShortcutBadge) {
    const isMac = (navigator.platform && navigator.platform.toUpperCase().includes('MAC')) || 
                  (navigator.userAgent && navigator.userAgent.includes('Mac'));
    elements.searchShortcutBadge.textContent = isMac ? '⌘K' : 'Ctrl K';
  }

  window.addEventListener('focus', clearBackgroundNotification);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      clearBackgroundNotification();
    }
  });

  setupEventListeners();

  window.addEventListener('auth:expired', () => {
    showToast('Session expired. Please log in again.');
    handleLogout(false);
  });

  const savedUserJson = localStorage.getItem('freeChat_user');
  const token = API.getToken();

  if (savedUserJson && token) {
    try {
      const user = JSON.parse(savedUserJson);
      // Validate token with backend
      const meRes = await API.getMe();
      const keys = await KeyStore.getUserKeys(user.id);

      if (keys?.privateKey && meRes.user) {
        state.currentUser = user;
        state.localPrivateKey = keys.privateKey;
        state.localPublicKey = keys.publicKey;
        onAuthSuccess();
        return;
      } else if (user.username) {
        // Vault session key expired or closed -> prompt password login to unlock vault
        showAuthModal('login');
        elements.authUsernameInput.value = user.username;
        elements.authPasswordInput.focus();
        return;
      }
    } catch (err) {
      console.warn('[Init] Session invalid or expired:', err);
      API.clearToken();
      localStorage.removeItem('freeChat_user');
    }
  }

  showAuthModal('login');
}

// Theme
function initTheme() {
  const savedTheme = localStorage.getItem('freeChat_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeColor(savedTheme);
  updateThemeIcon(savedTheme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';

  const applyTheme = () => {
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('freeChat_theme', next);
    updateThemeColor(next);
    updateThemeIcon(next);
  };

  triggerHaptic('light');

  if (document.startViewTransition) {
    document.startViewTransition(applyTheme);
  } else {
    applyTheme();
  }
}

function updateSoundToggleButton() {
  if (!elements.soundToggleBtn) return;
  const enabled = isSoundEnabled();
  elements.soundToggleBtn.classList.toggle('muted', !enabled);
  elements.soundToggleBtn.title = enabled ? 'Mute sound notifications' : 'Enable sound notifications';
  elements.soundToggleBtn.setAttribute('aria-label', enabled ? 'Mute sound notifications' : 'Enable sound notifications');
}

function updateThemeColor(theme) {
  const meta = elements.themeColorMeta || document.getElementById('theme-color-meta');
  if (meta) {
    meta.setAttribute('content', theme === 'dark' ? '#000000' : '#f2f2f7');
  }
}

function updateThemeIcon(theme) {
  if (!elements.themeToggleBtn) return;
  elements.themeToggleBtn.innerHTML = theme === 'dark' 
    ? `<svg aria-hidden="true" viewBox="0 0 24 24"><path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0s-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/></svg>`
    : `<svg aria-hidden="true" viewBox="0 0 24 24"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/></svg>`;
}

const ORIGINAL_TITLE = 'freeChat • Private E2EE Messenger';
const ORIGINAL_FAVICON = '/favicon.svg';
const BADGE_FAVICON = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="%230a84ff"/><stop offset="100%" stop-color="%23007aff"/></linearGradient></defs><rect width="32" height="32" rx="8" fill="url(%23g)"/><path d="M22 13h-1V10c0-2.76-2.24-5-5-5s-5 2.24-5 5v3h-1c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V15c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H12.9V10c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v3z" fill="%23ffffff"/><circle cx="26" cy="6" r="5" fill="%23ff3b30" stroke="%23ffffff" stroke-width="1.5"/></svg>';

function updateBackgroundNotification(senderName) {
  if (!document.hidden) return;
  state.unreadBackgroundCount++;
  document.title = `(${state.unreadBackgroundCount}) ${senderName || 'New Message'} • freeChat`;
  if (elements.appFavicon) {
    elements.appFavicon.href = BADGE_FAVICON;
  }
}

function clearBackgroundNotification() {
  state.unreadBackgroundCount = 0;
  document.title = ORIGINAL_TITLE;
  if (elements.appFavicon) {
    elements.appFavicon.href = ORIGINAL_FAVICON;
  }
}

// Auth modal
function showAuthModal(mode = 'login') {
  currentAuthMode = mode;
  elements.authModal.classList.add('active');
  elements.authCryptoStatus.textContent = '🔒 Zero-Knowledge Security Active';
  
  const authTabs = elements.tabLogin?.closest('.auth-tabs');
  if (authTabs) authTabs.dataset.tab = mode;

  if (mode === 'login') {
    elements.tabLogin.classList.add('active');
    elements.tabLogin.setAttribute('aria-selected', 'true');
    elements.tabRegister.classList.remove('active');
    elements.tabRegister.setAttribute('aria-selected', 'false');
    elements.authTitle.textContent = 'Welcome Back';
    elements.authSubtitle.textContent = 'Sign in with your private credentials';
    elements.authSubmitBtn.textContent = 'Sign In';
    elements.authPasswordInput.setAttribute('autocomplete', 'current-password');
  } else {
    elements.tabRegister.classList.add('active');
    elements.tabRegister.setAttribute('aria-selected', 'true');
    elements.tabLogin.classList.remove('active');
    elements.tabLogin.setAttribute('aria-selected', 'false');
    elements.authTitle.textContent = 'Create Identity';
    elements.authSubtitle.textContent = 'Generate your local E2EE keys';
    elements.authSubmitBtn.textContent = 'Create Account & Keys';
    elements.authPasswordInput.setAttribute('autocomplete', 'new-password');
  }
  elements.authUsernameInput.focus();
}

function hideAuthModal() {
  elements.authModal.classList.remove('active');
  elements.authForm.reset();
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const username = elements.authUsernameInput.value.trim().toLowerCase();
  const password = elements.authPasswordInput.value;

  if (!username || !password) {
    showToast('Please enter both username and password.');
    return;
  }

  elements.authSubmitBtn.disabled = true;

  try {
    if (currentAuthMode === 'register') {
      elements.authCryptoStatus.textContent = '🔑 Generating ECDH P-256 Key Pair...';
      const keyPair = await generateKeyPair();
      const publicKeyJwk = await exportPublicKey(keyPair.publicKey);

      elements.authCryptoStatus.textContent = '🛡️ Deriving Master Key...';
      const salt = generateRandomBytes(16);
      const saltBase64 = arrayBufferToBase64(salt);
      const masterKey = await deriveMasterKey(password, salt);
      const authVerifier = await deriveAuthVerifier(password, saltBase64);

      elements.authCryptoStatus.textContent = '🔒 Encrypting Key Backup...';
      const encryptedBackup = await encryptPrivateKeyBackup(keyPair.privateKey, masterKey);

      const colors = ['#007AFF', '#FF2D55', '#5856D6', '#AF52DE', '#FF9500', '#34C759'];
      const avatarColor = colors[Math.floor(Math.random() * colors.length)];

      elements.authCryptoStatus.textContent = '☁️ Creating Account...';
      const res = await API.register({
        username,
        auth_verifier: authVerifier,
        public_key: publicKeyJwk,
        encrypted_priv_key: encryptedBackup.encryptedPrivateKey,
        salt: saltBase64,
        iv: encryptedBackup.iv,
        avatar_color: avatarColor
      });

      await KeyStore.saveUserKeys(res.user.id, keyPair.privateKey, keyPair.publicKey);

      state.currentUser = res.user;
      // In-memory key is strictly non-extractable to prevent XSS export
      state.localPrivateKey = await importPrivateKey(await exportPrivateKey(keyPair.privateKey), false);
      state.localPublicKey = keyPair.publicKey;

      localStorage.setItem('freeChat_user', JSON.stringify(res.user));
      hideAuthModal();
      onAuthSuccess();
      showToast(`Welcome @${username}! Keys generated safely.`);
    } else {
      elements.authCryptoStatus.textContent = '🔍 Fetching parameters...';
      const preLogin = await API.preLogin(username);

      elements.authCryptoStatus.textContent = '🛡️ Deriving Key & Verifier...';
      const saltBuffer = base64ToArrayBuffer(preLogin.salt);
      const masterKey = await deriveMasterKey(password, saltBuffer);
      const authVerifier = await deriveAuthVerifier(password, preLogin.salt, preLogin.v || 2);

      elements.authCryptoStatus.textContent = '🔐 Authenticating...';
      const loginRes = await API.login(username, authVerifier);

      elements.authCryptoStatus.textContent = '🔓 Decrypting Private Key...';
      const privateKey = await decryptPrivateKeyBackup(
        loginRes.user.encrypted_priv_key,
        loginRes.user.iv,
        masterKey
      );

      const publicKey = await importPublicKey(loginRes.user.public_key);
      await KeyStore.saveUserKeys(loginRes.user.id, privateKey, publicKey);

      state.currentUser = loginRes.user;
      // In-memory key is strictly non-extractable
      const privJwk = await exportPrivateKey(privateKey);
      state.localPrivateKey = await importPrivateKey(privJwk, false);
      state.localPublicKey = publicKey;

      localStorage.setItem('freeChat_user', JSON.stringify(loginRes.user));
      hideAuthModal();
      onAuthSuccess();
      showToast(`Welcome back, @${username}!`);
    }
  } catch (err) {
    console.error('[Auth Error]:', err);
    elements.authCryptoStatus.textContent = '❌ Authentication failed';
    const authCard = elements.authModal.querySelector('.auth-card');
    if (authCard) {
      authCard.classList.remove('shake');
      void authCard.offsetWidth;
      authCard.classList.add('shake');
    }
    triggerHaptic('medium');
    showToast(err.message || 'Authentication error');
  } finally {
    elements.authSubmitBtn.disabled = false;
  }
}

function handleLogout(showConfirmation = true) {
  if (!showConfirmation || confirm('Are you sure you want to log out? Your keys remain securely encrypted.')) {
    if (state.currentUser) {
      KeyStore.clearUserKeys(state.currentUser.id);
    }
    clearSharedKeyCache();
    API.clearToken();
    localStorage.removeItem('freeChat_user');
    Realtime.disconnect();
    state.currentUser = null;
    state.localPrivateKey = null;
    state.localPublicKey = null;
    state.activeConversation = null;
    state.activeTargetUser = null;
    state.activeSharedKey = null;
    state.onlineUsers.clear();
    location.reload();
  }
}

function setConnectionStatus(status, text) {
  const bar = elements.connectionStatusBar || document.getElementById('connection-status-bar');
  const label = elements.connectionStatusText || document.getElementById('connection-status-text');
  if (!bar || !label) return;

  if (status === 'connected') {
    bar.className = 'connection-status-bar online';
    label.textContent = text || 'Connected to secure network';
    setTimeout(() => {
      bar.classList.add('hidden');
    }, 1500);
  } else if (status === 'connecting' || status === 'reconnecting') {
    bar.className = 'connection-status-bar';
    label.textContent = text || 'Connecting to real-time network...';
    bar.classList.remove('hidden');
  } else if (status === 'offline') {
    bar.className = 'connection-status-bar';
    label.textContent = text || 'Offline. Waiting for network...';
    bar.classList.remove('hidden');
  }
}

// Post-auth
async function onAuthSuccess() {
  elements.sidebarUsername.textContent = `@${state.currentUser.username}`;
  elements.sidebarAvatar.textContent = (state.currentUser.username || '?')[0].toUpperCase();
  elements.sidebarAvatar.style.backgroundColor = state.currentUser.avatar_color || '#007AFF';

  Realtime.connect({
    token: API.getToken(),
    onConnect: () => {
      setConnectionStatus('connected', 'Secure real-time network active');
    },
    onDisconnect: () => {
      setConnectionStatus('reconnecting', 'Connection lost. Reconnecting...');
    },
    onReconnectAttempt: () => {
      setConnectionStatus('reconnecting', 'Reconnecting to real-time network...');
    },
    onOnlineUsersList: (userIds) => {
      state.onlineUsers = new Set(userIds);
      renderConversationsList();
      updateChatHeaderPresence();
    },
    onMessageReceived: handleIncomingMessage,
    onTypingChange: handleTypingChange,
    onStatusChange: handleUserStatusChange,
    onConversationUpdated: () => loadConversations(),
    onConnectError: (err) => {
      console.warn('[Socket Connection Error]:', err.message);
      setConnectionStatus('reconnecting', 'Connection issue. Reconnecting...');
      if (err.message.includes('Authentication error') || err.message.includes('token')) {
        showToast('Realtime session expired. Please log in again.');
        handleLogout(false);
      }
    }
  });

  await loadConversations();
}

// Conversations
async function loadConversations() {
  if (state.conversations.length === 0 && elements.conversationsList) {
    renderConversationSkeletons(elements.conversationsList);
  }
  try {
    const convs = await API.getConversations();
    state.conversations = convs;
    renderConversationsList();
  } catch (err) {
    console.error('[Conversations Error]:', err);
  }
}

function renderConversationsList() {
  const q = state.searchQuery.toLowerCase().trim();
  const filteredConvs = q ? state.conversations.filter(c => {
    const otherParticipant = c.conversation_participants?.find(
      p => (p.user_id || p.users?.id) !== state.currentUser.id
    )?.users;
    return otherParticipant?.username?.toLowerCase().includes(q) || c.title?.toLowerCase().includes(q);
  }) : state.conversations;

  if (filteredConvs.length === 0) {
    elements.conversationsList.innerHTML = `
      <div style="padding: 28px 16px; text-align: center; color: var(--text-secondary); font-size: 14px; display: flex; flex-direction: column; align-items: center; gap: 12px;">
        <p>${q ? `No conversations matching "<strong>${escapeHtml(q)}</strong>"` : 'No conversations yet.'}</p>
        <button class="glass-btn glass-btn-primary" id="sidebar-new-chat-cta" style="padding: 7px 16px; font-size: 13px;">
          ${q ? 'Clear Search' : 'Start a Chat'}
        </button>
      </div>
    `;
    const cta = document.getElementById('sidebar-new-chat-cta');
    if (cta) {
      cta.addEventListener('click', () => {
        if (q) {
          if (elements.searchConvInput) elements.searchConvInput.value = '';
          state.searchQuery = '';
          renderConversationsList();
        } else {
          openNewChatModal();
        }
      });
    }
    return;
  }

  // 1. FIRST: Capture current vertical positions of all existing conversation elements
  const firstPositions = new Map();
  const existingElements = new Map();
  elements.conversationsList.querySelectorAll('.conv-item').forEach(el => {
    const id = el.dataset.convId;
    if (id) {
      firstPositions.set(id, el.getBoundingClientRect().top);
      existingElements.set(id, el);
    }
  });

  // Remove empty state message if it was present
  if (elements.conversationsList.querySelector('#sidebar-new-chat-cta')) {
    elements.conversationsList.innerHTML = '';
    existingElements.clear();
    firstPositions.clear();
  }

  // Remove elements that no longer match the filter
  const validIds = new Set(filteredConvs.map(c => c.id));
  existingElements.forEach((el, id) => {
    if (!validIds.has(id)) {
      el.remove();
      existingElements.delete(id);
      firstPositions.delete(id);
    }
  });

  // 2. Build or update items in sorted order
  filteredConvs.forEach(conv => {
    const isActive = state.activeConversation?.id === conv.id;
    let item = existingElements.get(conv.id);

    if (item) {
      // Update active state
      item.classList.toggle('active', isActive);

      // Update time if available
      const timeEl = item.querySelector('.conv-item-time');
      if (timeEl && conv.updated_at) {
        timeEl.textContent = formatTime(conv.updated_at);
      }

      // Update presence badge
      const otherParticipant = conv.conversation_participants?.find(
        p => (p.user_id || p.users?.id) !== state.currentUser.id
      )?.users;
      if (otherParticipant?.id) {
        const badge = item.querySelector('.avatar-status-badge');
        if (badge) {
          const isOnline = state.onlineUsers.has(otherParticipant.id);
          badge.classList.toggle('offline', !isOnline);
        }
      }

      // Re-append to ensure DOM order matches sorted order
      elements.conversationsList.appendChild(item);
    } else {
      // Create new item
      item = renderConversationItem(conv, state.currentUser.id, isActive, state.onlineUsers);

      item.addEventListener('click', (e) => {
        e.preventDefault();
        selectConversation(conv);
      });

      item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          selectConversation(conv);
        }
      });

      elements.conversationsList.appendChild(item);
    }

    // Decrypt last message snippet
    if (conv.last_message && state.localPrivateKey) {
      const otherParticipant = conv.conversation_participants?.find(
        p => (p.user_id || p.users?.id) !== state.currentUser.id
      )?.users;

      if (otherParticipant?.public_key) {
        getSharedSecretKey(state.localPrivateKey, otherParticipant.public_key, otherParticipant.id)
          .then(sharedKey => decryptMessage(conv.last_message.ciphertext, conv.last_message.iv, sharedKey))
          .then(plain => {
            const previewEl = document.getElementById(`conv-preview-${conv.id}`);
            if (previewEl && plain && !plain.startsWith('🔒')) {
              const prefix = conv.last_message.sender_id === state.currentUser.id ? 'You: ' : '';
              previewEl.textContent = `${prefix}${plain}`;
            }
          })
          .catch(() => {});
      }
    }
  });

  // 3. LAST & INVERT: Measure new positions and compute delta
  if (firstPositions.size > 0) {
    const lastPositions = new Map();
    elements.conversationsList.querySelectorAll('.conv-item').forEach(el => {
      const id = el.dataset.convId;
      if (id) {
        lastPositions.set(id, el.getBoundingClientRect().top);
      }
    });

    elements.conversationsList.querySelectorAll('.conv-item').forEach(el => {
      const id = el.dataset.convId;
      if (!id) return;

      if (firstPositions.has(id)) {
        const deltaY = firstPositions.get(id) - lastPositions.get(id);
        if (deltaY !== 0) {
          el.style.transform = `translateY(${deltaY}px)`;
          el.style.transition = 'none';
        }
      } else {
        // Brand new conversation item: animate in smoothly
        el.classList.add('new-item');
      }
    });

    // 4. PLAY: Transition to final position
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        elements.conversationsList.querySelectorAll('.conv-item').forEach(el => {
          if (el.style.transform) {
            el.style.transition = 'transform 0.35s var(--spring-overshoot)';
            el.style.transform = '';
            const onEnd = () => {
              el.style.transition = '';
              el.removeEventListener('transitionend', onEnd);
            };
            el.addEventListener('transitionend', onEnd, { once: true });
          }
        });
      });
    });
  }
}

function updateChatHeaderPresence() {
  if (!state.activeTargetUser) return;
  const isOnline = state.onlineUsers.has(state.activeTargetUser.id);

  if (state.activeKeyChanged) {
    elements.chatHeaderSubtitle.innerHTML = `<span style="color: var(--danger, #ff3b30); font-weight:600; cursor:pointer;" title="Click to view safety number">⚠️ Key Changed! Verify Safety Number</span>`;
  } else {
    elements.chatHeaderSubtitle.innerHTML = isOnline
      ? `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background-color:var(--status-online); margin-right:4px;"></span> Online • E2EE 🔒`
      : `<svg class="e2e-lock-icon" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg> freeChat • End-to-End Encrypted`;
  }

  // Update verified badge in header
  if (elements.headerVerifiedBadge) {
    elements.headerVerifiedBadge.style.display = state.activeContactVerified ? 'inline-flex' : 'none';
  }
}

async function selectConversation(conv) {
  // Mobile navigation history support
  const isMobile = window.matchMedia('(max-width: 768px)').matches;
  if (isMobile && !document.body.classList.contains('chat-active')) {
    history.pushState({ chatActive: true }, '');
  }

  // Always bring UI into view immediately
  document.body.classList.add('chat-active');
  elements.emptyChatState.style.display = 'none';
  elements.activeChatView.style.display = 'flex';

  state.unreadWhileScrolledCount = 0;
  if (elements.scrollBottomBtn) elements.scrollBottomBtn.classList.add('hidden');
  if (elements.scrollBottomBadge) elements.scrollBottomBadge.classList.add('hidden');

  const isAlreadyActive = state.activeConversation?.id === conv.id;

  if (isAlreadyActive) {
    elements.composerInput.focus();
    scrollToBottom(elements.messagesContainer, true);
    return;
  }

  // Leave previous room and save draft
  if (state.activeConversation) {
    state.drafts[state.activeConversation.id] = elements.composerInput.value;
    Realtime.leaveConversation(state.activeConversation.id);
  }

  state.activeConversation = conv;
  Realtime.joinConversation(conv.id);

  // Target user
  const otherParticipant = conv.conversation_participants?.find(
    p => (p.user_id || p.users?.id) !== state.currentUser.id
  )?.users;

  state.activeTargetUser = otherParticipant;

  // Key exchange & Safety Number
  try {
    if (otherParticipant?.public_key) {
      state.activeSharedKey = await getSharedSecretKey(
        state.localPrivateKey,
        otherParticipant.public_key,
        otherParticipant.id
      );

      if (state.localPublicKey) {
        const localJwk = await exportPublicKey(state.localPublicKey);
        const safety = await computeSafetyNumber(localJwk, otherParticipant.public_key);
        state.activeSafetyNumber = safety.safetyNumber;
        state.activeSafetyBlocks = safety.blocks;
        state.activeFingerprint = safety.fingerprint;

        const stored = VerifiedKeys.get(state.currentUser.id, otherParticipant.id);
        if (stored) {
          if (stored.fingerprint !== safety.fingerprint) {
            state.activeKeyChanged = true;
            state.activeContactVerified = false;
          } else {
            state.activeKeyChanged = false;
            state.activeContactVerified = Boolean(stored.verified);
          }
        } else {
          state.activeKeyChanged = false;
          state.activeContactVerified = false;
        }
      }
    } else {
      state.activeSafetyNumber = null;
      state.activeSafetyBlocks = [];
      state.activeFingerprint = null;
      state.activeContactVerified = false;
      state.activeKeyChanged = false;
    }
  } catch (err) {
    console.error('[Key Exchange / Safety Number Error]:', err);
    showToast('Failed to establish E2EE key exchange.');
  }

  const targetName = otherParticipant?.username || 'Chat';
  elements.chatHeaderName.textContent = targetName;
  elements.chatHeaderAvatar.textContent = targetName[0].toUpperCase();
  elements.chatHeaderAvatar.style.backgroundColor = otherParticipant?.avatar_color || '#007AFF';
  updateChatHeaderPresence();

  renderConversationsList();
  await loadMessages(conv.id);

  // Restore unsent draft if available
  const savedDraft = state.drafts[conv.id] || '';
  elements.composerInput.value = savedDraft;
  elements.composerInput.style.height = 'auto';
  if (savedDraft.trim().length > 0) {
    elements.composerInput.style.height = Math.min(elements.composerInput.scrollHeight, 120) + 'px';
  }
  updateSendButtonState();
  elements.composerInput.focus();
}

function isMessagesScrolledNearBottom() {
  if (!elements.messagesContainer) return true;
  const threshold = 120;
  const distanceFromBottom = elements.messagesContainer.scrollHeight - elements.messagesContainer.scrollTop - elements.messagesContainer.clientHeight;
  return distanceFromBottom <= threshold;
}

function updateScrollBottomButtonVisibility() {
  if (!elements.scrollBottomBtn || !elements.messagesContainer) return;
  const isNear = isMessagesScrolledNearBottom();
  const distanceFromBottom = elements.messagesContainer.scrollHeight - elements.messagesContainer.scrollTop - elements.messagesContainer.clientHeight;

  if (isNear) {
    state.unreadWhileScrolledCount = 0;
    elements.scrollBottomBtn.classList.add('hidden');
    if (elements.scrollBottomBadge) elements.scrollBottomBadge.classList.add('hidden');
  } else {
    if (state.unreadWhileScrolledCount > 0) {
      if (elements.scrollBottomText) {
        elements.scrollBottomText.textContent = state.unreadWhileScrolledCount === 1 ? 'New Message' : 'New Messages';
      }
      if (elements.scrollBottomBadge) {
        elements.scrollBottomBadge.textContent = String(state.unreadWhileScrolledCount);
        elements.scrollBottomBadge.classList.remove('hidden');
        elements.scrollBottomBadge.classList.remove('bump');
        void elements.scrollBottomBadge.offsetWidth;
        elements.scrollBottomBadge.classList.add('bump');
      }
      elements.scrollBottomBtn.classList.remove('hidden');
    } else if (distanceFromBottom > 240) {
      if (elements.scrollBottomText) {
        elements.scrollBottomText.textContent = 'Latest Messages';
      }
      if (elements.scrollBottomBadge) elements.scrollBottomBadge.classList.add('hidden');
      elements.scrollBottomBtn.classList.remove('hidden');
    } else {
      elements.scrollBottomBtn.classList.add('hidden');
    }
  }
}

function ensureDateDivider(createdAt) {
  const msgDate = new Date(createdAt).toDateString();
  const dividers = elements.messagesContainer.querySelectorAll('.date-divider');
  const lastDivider = dividers[dividers.length - 1];
  if (!lastDivider || lastDivider.dataset.date !== msgDate) {
    const divider = renderDateDivider(formatDateDivider(createdAt));
    divider.dataset.date = msgDate;
    elements.messagesContainer.appendChild(divider);
  }
}

async function loadMessages(convId) {
  renderMessageSkeletons(elements.messagesContainer);

  try {
    const messages = await API.getMessages(convId);
    if (state.activeConversation?.id !== convId) return;

    elements.messagesContainer.innerHTML = '';

    if (messages.length === 0) {
      elements.messagesContainer.innerHTML = `
        <div style="text-align:center; padding: 24px; color: var(--text-secondary); font-size: 13px;">
          🔒 No messages yet. Say hello to start an encrypted conversation!
        </div>
      `;
      return;
    }

    let lastDateStr = null;

    for (let i = 0; i < messages.length; i++) {
      const msg = messages[i];
      const nextMsg = messages[i + 1];
      const isMine = msg.sender_id === state.currentUser.id;

      const isLastInCluster = !nextMsg || nextMsg.sender_id !== msg.sender_id ||
        (new Date(nextMsg.created_at) - new Date(msg.created_at) > 120000);

      const msgDate = new Date(msg.created_at).toDateString();
      if (msgDate !== lastDateStr) {
        lastDateStr = msgDate;
        const divider = renderDateDivider(formatDateDivider(msg.created_at));
        divider.dataset.date = msgDate;
        elements.messagesContainer.appendChild(divider);
      }

      let plainText = '🔒 [Encrypted Message]';

      if (state.activeSharedKey) {
        plainText = await decryptMessage(msg.ciphertext, msg.iv, state.activeSharedKey);
      }

      const bubble = renderMessageBubble({
        id: msg.id,
        isMine,
        plainText,
        createdAt: msg.created_at,
        isLastInCluster,
        isLive: false
      });
      elements.messagesContainer.appendChild(bubble);
    }

    scrollToBottom(elements.messagesContainer, false);
  } catch (err) {
    console.error('[Messages Error]:', err);
  }
}

// Send message
async function handleSendMessage() {
  const text = elements.composerInput.value.trim();
  if (!text || !state.activeConversation || !state.activeSharedKey) return;

  elements.sendBtn.classList.add('sending');
  setTimeout(() => elements.sendBtn.classList.remove('sending'), 120);

  elements.composerInput.value = '';
  elements.composerInput.style.height = 'auto';
  updateSendButtonState();

  try {
    const { ciphertext, iv } = await encryptMessage(text, state.activeSharedKey);

    const savedMsg = await Realtime.sendMessage({
      conversationId: state.activeConversation.id,
      senderId: state.currentUser.id,
      ciphertext,
      iv
    });

    ensureDateDivider(savedMsg.created_at);

    // If the previous message was also sent by me within 2 minutes, cluster it and transition its tail
    const lastRow = elements.messagesContainer.querySelector('.message-row:last-child');
    const isRecent = lastRow?.dataset.timestamp && (Date.now() - Number(lastRow.dataset.timestamp) < 120000);
    if (lastRow && lastRow.classList.contains('sent') && isRecent) {
      lastRow.classList.remove('has-tail');
      lastRow.classList.add('clustered');
    }

    const bubble = renderMessageBubble({
      id: savedMsg.id,
      isMine: true,
      plainText: text,
      createdAt: savedMsg.created_at,
      isLastInCluster: true,
      isLive: true
    });
    elements.messagesContainer.appendChild(bubble);
    scrollToBottom(elements.messagesContainer, true);
    playSentSound();
    triggerHaptic('light');
    state.lastSentText = text;
    if (state.activeConversation) {
      delete state.drafts[state.activeConversation.id];
    }
    state.unreadWhileScrolledCount = 0;
    if (elements.scrollBottomBtn) elements.scrollBottomBtn.classList.add('hidden');
    if (elements.scrollBottomBadge) elements.scrollBottomBadge.classList.add('hidden');

    // Update conversation in sidebar
    state.activeConversation.last_message = savedMsg;
    state.activeConversation.updated_at = savedMsg.created_at;
    state.conversations.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
    renderConversationsList();

    Realtime.sendTypingStop(state.activeConversation.id);
  } catch (err) {
    console.error('[Send Error]:', err);
    showToast('Failed to send encrypted message.');

    // Render failed message bubble with tap-to-retry
    const failedBubble = renderMessageBubble({
      id: 'failed-' + Date.now(),
      isMine: true,
      plainText: text,
      createdAt: new Date().toISOString(),
      isLastInCluster: true,
      isFailed: true,
      isLive: true,
      onRetry: (retryText, failedRow) => {
        failedRow.remove();
        elements.composerInput.value = retryText;
        elements.composerInput.style.height = 'auto';
        elements.composerInput.style.height = Math.min(elements.composerInput.scrollHeight, 120) + 'px';
        updateSendButtonState();
        handleSendMessage();
      }
    });
    elements.messagesContainer.appendChild(failedBubble);
    scrollToBottom(elements.messagesContainer, true);
  }
}

// Receive message
async function handleIncomingMessage(msg) {
  if (state.activeConversation && msg.conversation_id === state.activeConversation.id) {
    if (msg.sender_id !== state.currentUser.id) {
      let plainText = '🔒 [Encrypted Message]';
      if (state.activeSharedKey) {
        plainText = await decryptMessage(msg.ciphertext, msg.iv, state.activeSharedKey);
      }

      removeTypingIndicator(true);

      ensureDateDivider(msg.created_at);

      // If the previous message was also received within 2 minutes, cluster it and transition its tail
      const lastRow = elements.messagesContainer.querySelector('.message-row:last-child');
      const isRecent = lastRow?.dataset.timestamp && (new Date(msg.created_at).getTime() - Number(lastRow.dataset.timestamp) < 120000);
      if (lastRow && lastRow.classList.contains('received') && isRecent) {
        lastRow.classList.remove('has-tail');
        lastRow.classList.add('clustered');
      }

      const wasNearBottom = isMessagesScrolledNearBottom();
      const bubble = renderMessageBubble({
        id: msg.id,
        isMine: false,
        plainText,
        createdAt: msg.created_at,
        isLastInCluster: true,
        isLive: true
      });
      elements.messagesContainer.appendChild(bubble);

      playReceivedSound();
      triggerHaptic('double');
      updateBackgroundNotification(state.activeTargetUser?.username || 'New Message');

      if (wasNearBottom) {
        scrollToBottom(elements.messagesContainer, true);
      } else {
        state.unreadWhileScrolledCount++;
        updateScrollBottomButtonVisibility();
      }
    }
  } else if (msg.sender_id !== state.currentUser?.id) {
    updateBackgroundNotification('New Message');
  }

  loadConversations();
}

// Typing indicators
function handleTypingInput() {
  // Auto-resize composer textarea with fallback
  elements.composerInput.style.height = 'auto';
  if (elements.composerInput.value.trim().length > 0) {
    elements.composerInput.style.height = Math.min(elements.composerInput.scrollHeight, 120) + 'px';
  }

  updateSendButtonState();

  if (!state.activeConversation) return;

  if (!state.isTyping) {
    state.isTyping = true;
    Realtime.sendTypingStart(state.activeConversation.id);
  }

  clearTimeout(state.isTypingTimer);
  state.isTypingTimer = setTimeout(() => {
    state.isTyping = false;
    Realtime.sendTypingStop(state.activeConversation.id);
  }, 2000);
}

let remoteTypingTimeout = null;

function handleTypingChange({ conversationId, username, isTyping }) {
  if (state.activeConversation?.id !== conversationId) return;

  const existing = document.getElementById('active-typing-indicator');

  clearTimeout(remoteTypingTimeout);

  if (isTyping) {
    if (!existing) {
      const typingBubble = renderTypingIndicator(username);
      elements.messagesContainer.appendChild(typingBubble);
      if (isMessagesScrolledNearBottom()) {
        scrollToBottom(elements.messagesContainer, true);
      }
    }
    // Auto-cleanup after 4 seconds if remote user closes tab or loses connection
    remoteTypingTimeout = setTimeout(() => {
      removeTypingIndicator();
    }, 4000);
  } else if (existing) {
    removeTypingIndicator();
  }
}

function handleUserStatusChange({ userId, status }) {
  if (status === 'online') {
    state.onlineUsers.add(userId);
  } else {
    state.onlineUsers.delete(userId);
  }

  const badge = document.getElementById(`status-badge-${userId}`);
  if (badge) {
    if (status === 'online') {
      badge.classList.remove('offline');
    } else {
      badge.classList.add('offline');
    }
  }

  updateChatHeaderPresence();
}

function updateSendButtonState() {
  const hasText = elements.composerInput.value.trim().length > 0;
  if (hasText) {
    elements.sendBtn.classList.add('active');
  } else {
    elements.sendBtn.classList.remove('active');
  }
}

// Modal focus trap helper
function trapModalFocus(modalEl, e) {
  if (e.key !== 'Tab') return;
  const focusables = modalEl.querySelectorAll(
    'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  );
  if (!focusables || focusables.length === 0) return;

  const first = focusables[0];
  const last = focusables[focusables.length - 1];

  if (e.shiftKey) {
    if (document.activeElement === first) {
      e.preventDefault();
      last.focus();
    }
  } else {
    if (document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }
}

let lastFocusedElementBeforeModal = null;

// User search
function openNewChatModal() {
  lastFocusedElementBeforeModal = document.activeElement;
  elements.newChatModal.classList.add('active');
  elements.userSearchInput.value = '';
  elements.searchResultsList.innerHTML = '';
  elements.userSearchInput.focus();
}

function closeNewChatModal() {
  elements.newChatModal.classList.remove('active');
  if (lastFocusedElementBeforeModal && typeof lastFocusedElementBeforeModal.focus === 'function') {
    lastFocusedElementBeforeModal.focus();
  }
}

let searchDebounceTimer = null;
async function handleUserSearch() {
  const query = elements.userSearchInput.value.trim();
  clearTimeout(searchDebounceTimer);

  if (query.length < 1) {
    elements.searchResultsList.innerHTML = '';
    return;
  }

  searchDebounceTimer = setTimeout(async () => {
    try {
      const results = await API.searchUsers(query);
      elements.searchResultsList.innerHTML = '';

      if (results.length === 0) {
        elements.searchResultsList.innerHTML = `
          <div style="padding: 16px; text-align: center; color: var(--text-secondary); font-size: 13px;">
            No users found matching "${escapeHtml(query)}"
          </div>
        `;
        return;
      }

      results.forEach(user => {
        const item = document.createElement('div');
        item.className = 'search-result-item';
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', `Start chat with @${user.username}`);
        const initial = escapeHtml((user.username || '?')[0].toUpperCase());
        const rawColor = user.avatar_color || '#007AFF';
        const avatarColor = /^#[0-9a-fA-F]{3,8}$/.test(rawColor) ? rawColor : '#007AFF';

        item.innerHTML = `
          <div style="display: flex; align-items: center; gap: 10px;">
            <div class="avatar" style="background-color: ${avatarColor}; width: 36px; height: 36px; font-size: 14px;" aria-hidden="true">
              ${initial}
            </div>
            <div>
              <div style="font-weight: 600; font-size: 15px;">@${escapeHtml(user.username)}</div>
              <div style="font-size: 12px; color: var(--text-secondary);">E2EE Public Key Ready 🔒</div>
            </div>
          </div>
          <button class="glass-btn glass-btn-primary" style="padding: 6px 14px; font-size: 13px;" tabindex="-1" aria-hidden="true">Chat</button>
        `;

        item.addEventListener('click', () => startDirectChatWith(user.username));
        item.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            startDirectChatWith(user.username);
          }
        });
        elements.searchResultsList.appendChild(item);
      });
    } catch (err) {
      console.error('[Search Error]:', err);
    }
  }, 250);
}

async function startDirectChatWith(targetUsername) {
  closeNewChatModal();
  try {
    const conv = await API.createDirectConversation(targetUsername);
    await loadConversations();
    selectConversation(conv);
  } catch (err) {
    console.error('[Chat Error]:', err);
    showToast(err.message || 'Failed to start conversation.');
  }
}

// Safety Number & Key Verification
async function openSafetyNumberModal() {
  if (!state.activeTargetUser) return;
  lastFocusedElementBeforeModal = document.activeElement;
  elements.safetyRecipientName.textContent = `@${state.activeTargetUser.username}`;

  // If safety number hasn't been computed yet, compute it now
  if (!state.activeSafetyNumber && state.localPublicKey && state.activeTargetUser.public_key) {
    try {
      const localJwk = await exportPublicKey(state.localPublicKey);
      const safety = await computeSafetyNumber(localJwk, state.activeTargetUser.public_key);
      state.activeSafetyNumber = safety.safetyNumber;
      state.activeSafetyBlocks = safety.blocks;
      state.activeFingerprint = safety.fingerprint;
    } catch (err) {
      console.error('[Safety Number Computation Error]:', err);
    }
  }

  // Render grid blocks
  elements.safetyNumberGrid.innerHTML = '';
  if (state.activeSafetyBlocks && state.activeSafetyBlocks.length > 0) {
    state.activeSafetyBlocks.forEach(block => {
      const blockEl = document.createElement('div');
      blockEl.className = 'safety-number-block';
      blockEl.textContent = block;
      elements.safetyNumberGrid.appendChild(blockEl);
    });
  } else {
    elements.safetyNumberGrid.textContent = 'Safety number unavailable';
  }

  // Fingerprint
  elements.safetyFingerprintDisplay.textContent = state.activeFingerprint || '—';

  // Key changed alert banner
  if (state.activeKeyChanged) {
    elements.safetyAlertBanner.style.display = 'flex';
  } else {
    elements.safetyAlertBanner.style.display = 'none';
  }

  // Toggle button text & style
  updateSafetyVerifyButtonState();

  elements.safetyNumberModal.classList.add('active');
  elements.btnCopySafetyNumber.focus();
}

function updateSafetyVerifyButtonState() {
  if (state.activeContactVerified) {
    elements.btnToggleVerifyContact.textContent = 'Clear Verification';
    elements.btnToggleVerifyContact.classList.remove('glass-btn-primary');
  } else {
    elements.btnToggleVerifyContact.textContent = 'Mark as Verified';
    elements.btnToggleVerifyContact.classList.add('glass-btn-primary');
  }
}

function closeSafetyNumberModal() {
  elements.safetyNumberModal.classList.remove('active');
  if (lastFocusedElementBeforeModal && typeof lastFocusedElementBeforeModal.focus === 'function') {
    lastFocusedElementBeforeModal.focus();
  }
}

async function handleCopySafetyNumber() {
  if (!state.activeSafetyNumber) return;
  try {
    await navigator.clipboard.writeText(state.activeSafetyNumber);
    const origText = elements.btnCopySafetyNumber.textContent;
    elements.btnCopySafetyNumber.textContent = 'Copied!';
    setTimeout(() => {
      elements.btnCopySafetyNumber.textContent = origText;
    }, 2000);
    showToast('Safety number copied to clipboard');
  } catch (err) {
    console.error('Clipboard copy failed:', err);
    showToast('Failed to copy to clipboard');
  }
}

function handleToggleVerifyContact() {
  if (!state.activeTargetUser || !state.activeFingerprint) return;

  if (state.activeContactVerified) {
    // Unmark verification
    VerifiedKeys.remove(state.currentUser.id, state.activeTargetUser.id);
    state.activeContactVerified = false;
    state.activeKeyChanged = false;
    showToast(`Verification cleared for @${state.activeTargetUser.username}`);
  } else {
    // Mark as verified
    VerifiedKeys.set(state.currentUser.id, state.activeTargetUser.id, state.activeFingerprint, true);
    state.activeContactVerified = true;
    state.activeKeyChanged = false;
    showToast(`@${state.activeTargetUser.username} marked as verified 🔒`);
  }

  updateSafetyVerifyButtonState();
  elements.safetyAlertBanner.style.display = 'none';
  updateChatHeaderPresence();
}

// Event listeners
function setupEventListeners() {
  if (elements.soundToggleBtn) {
    elements.soundToggleBtn.addEventListener('click', () => {
      toggleSoundEnabled();
      updateSoundToggleButton();
      triggerHaptic('light');
    });
  }

  elements.themeToggleBtn.addEventListener('click', toggleTheme);

  elements.tabLogin.addEventListener('click', () => showAuthModal('login'));
  elements.tabRegister.addEventListener('click', () => showAuthModal('register'));
  elements.authForm.addEventListener('submit', handleAuthSubmit);
  elements.logoutBtn.addEventListener('click', handleLogout);

  elements.newChatBtn.addEventListener('click', openNewChatModal);
  if (elements.emptyChatStartBtn) {
    elements.emptyChatStartBtn.addEventListener('click', openNewChatModal);
  }
  elements.closeNewChatBtn.addEventListener('click', closeNewChatModal);
  elements.userSearchInput.addEventListener('input', handleUserSearch);

  // Safety Number & Key Verification listeners
  if (elements.btnVerifySafetyNumber) {
    elements.btnVerifySafetyNumber.addEventListener('click', openSafetyNumberModal);
  }
  if (elements.chatHeaderSubtitle) {
    elements.chatHeaderSubtitle.addEventListener('click', () => {
      if (state.activeKeyChanged) {
        openSafetyNumberModal();
      }
    });
  }
  if (elements.closeSafetyModalBtn) {
    elements.closeSafetyModalBtn.addEventListener('click', closeSafetyNumberModal);
  }
  if (elements.btnCopySafetyNumber) {
    elements.btnCopySafetyNumber.addEventListener('click', handleCopySafetyNumber);
  }
  if (elements.btnToggleVerifyContact) {
    elements.btnToggleVerifyContact.addEventListener('click', handleToggleVerifyContact);
  }

  // Network offline and online detection
  window.addEventListener('online', () => {
    setConnectionStatus('connecting', 'Network restored. Connecting...');
  });
  window.addEventListener('offline', () => {
    setConnectionStatus('offline', 'No internet connection. Waiting for network...');
  });

  if (elements.searchConvInput) {
    elements.searchConvInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      renderConversationsList();
    });
    elements.searchConvInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        elements.searchConvInput.value = '';
        state.searchQuery = '';
        renderConversationsList();
        elements.searchConvInput.blur();
      }
    });
  }

  // Backdrop click modal close
  elements.newChatModal.addEventListener('click', (e) => {
    if (e.target === elements.newChatModal) {
      closeNewChatModal();
    }
  });
  if (elements.safetyNumberModal) {
    elements.safetyNumberModal.addEventListener('click', (e) => {
      if (e.target === elements.safetyNumberModal) {
        closeSafetyNumberModal();
      }
    });
  }

  // Modal keyboard handling (focus trap & Escape)
  window.addEventListener('keydown', (e) => {
    if (elements.newChatModal.classList.contains('active')) {
      if (e.key === 'Escape') {
        closeNewChatModal();
        return;
      }
      trapModalFocus(elements.newChatModal, e);
    } else if (elements.authModal.classList.contains('active')) {
      trapModalFocus(elements.authModal, e);
    } else if (elements.safetyNumberModal?.classList.contains('active')) {
      if (e.key === 'Escape') {
        closeSafetyNumberModal();
        return;
      }
      trapModalFocus(elements.safetyNumberModal, e);
    }
  });

  // Global spotlight search shortcut (Cmd+K / Ctrl+K)
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (elements.searchConvInput) {
        elements.searchConvInput.focus();
        elements.searchConvInput.select();
      }
    }
  });

  elements.composerInput.addEventListener('input', handleTypingInput);
  elements.composerInput.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp' && elements.composerInput.value.trim() === '' && state.lastSentText) {
      e.preventDefault();
      elements.composerInput.value = state.lastSentText;
      elements.composerInput.style.height = 'auto';
      elements.composerInput.style.height = Math.min(elements.composerInput.scrollHeight, 120) + 'px';
      elements.composerInput.setSelectionRange(state.lastSentText.length, state.lastSentText.length);
      updateSendButtonState();
      return;
    }

    const isMobileViewport = window.matchMedia('(max-width: 768px)').matches;
    if (e.key === 'Enter' && !e.shiftKey) {
      if (isMobileViewport) {
        // On mobile keyboards, allow Return to create a newline
        return;
      }
      e.preventDefault();
      handleSendMessage();
    }
  });
  elements.sendBtn.addEventListener('click', handleSendMessage);

  if (elements.messagesContainer) {
    elements.messagesContainer.addEventListener('scroll', () => {
      updateScrollBottomButtonVisibility();
    }, { passive: true });
  }

  if (elements.scrollBottomBtn) {
    elements.scrollBottomBtn.addEventListener('click', () => {
      scrollToBottom(elements.messagesContainer, true);
      state.unreadWhileScrolledCount = 0;
      elements.scrollBottomBtn.classList.add('hidden');
      if (elements.scrollBottomBadge) elements.scrollBottomBadge.classList.add('hidden');
    });
  }

  elements.btnBack.addEventListener('click', () => {
    if (window.history.state?.chatActive) {
      window.history.back();
    } else {
      document.body.classList.remove('chat-active');
    }
  });

  window.addEventListener('popstate', (e) => {
    if (!e.state?.chatActive) {
      document.body.classList.remove('chat-active');
    }
  });
}

// Init
window.addEventListener('DOMContentLoaded', initApp);
