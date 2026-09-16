export function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

export function formatTime(dateInput) {
  if (!dateInput) return '';
  const date = new Date(dateInput);
  return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

export function formatDateDivider(dateInput) {
  if (!dateInput) return '';
  const date = new Date(dateInput);
  const now = new Date();
  
  const isToday = date.toDateString() === now.toDateString();
  const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
  const isYesterday = date.toDateString() === yesterday.toDateString();

  if (isToday) return 'Today';
  if (isYesterday) return 'Yesterday';

  const isCurrentYear = date.getFullYear() === now.getFullYear();
  return isCurrentYear
    ? date.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })
    : date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
}

export function linkify(escapedText) {
  if (!escapedText) return '';
  const urlRegex = /(https?:\/\/[^\s<&]+|www\.[^\s<&]+)/gi;
  return escapedText.replace(urlRegex, (match) => {
    const cleanUrl = match.replace(/[.,;:!?]+$/, '');
    const trailing = match.slice(cleanUrl.length);
    const href = cleanUrl.startsWith('www.') ? `https://${cleanUrl}` : cleanUrl;
    return `<a href="${href}" target="_blank" rel="noopener noreferrer" class="bubble-link">${cleanUrl}</a>${trailing}`;
  });
}

export function isEmojiOnly(text) {
  if (!text) return false;
  const trimmed = text.trim();
  if (!trimmed) return false;
  const emojiOnlyRegex = /^(\p{Extended_Pictographic}|\p{Emoji_Presentation}|\p{Emoji_Modifier}|\p{Emoji_Component}|\uFE0F|\u200D|\s)+$/u;
  if (!emojiOnlyRegex.test(trimmed)) return false;
  const countRegex = /\p{Extended_Pictographic}/gu;
  const matches = trimmed.match(countRegex);
  return Boolean(matches && matches.length >= 1 && matches.length <= 3);
}

export function showToast(message, duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'ios-toast';
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');
  toast.innerHTML = `
    <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
    </svg>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('hide');
    toast.addEventListener('animationend', () => toast.remove());
  }, duration);
}

export function renderDateDivider(text) {
  const div = document.createElement('div');
  div.className = 'date-divider';
  div.textContent = text;
  return div;
}

export function triggerHaptic(type = 'light') {
  if (typeof navigator === 'undefined' || !('vibrate' in navigator)) return;
  try {
    switch (type) {
      case 'light':
        navigator.vibrate(8);
        break;
      case 'medium':
        navigator.vibrate(15);
        break;
      case 'double':
        navigator.vibrate([10, 40, 10]);
        break;
    }
  } catch (e) {}
}

export function renderMessageSkeletons(container) {
  if (!container) return;
  container.innerHTML = `
    <div class="skeleton-bubble-row received">
      <div class="skeleton-bubble glass-skeleton" style="width: 55%; height: 42px;"></div>
    </div>
    <div class="skeleton-bubble-row sent">
      <div class="skeleton-bubble glass-skeleton" style="width: 42%; height: 38px;"></div>
    </div>
    <div class="skeleton-bubble-row received">
      <div class="skeleton-bubble glass-skeleton" style="width: 68%; height: 56px;"></div>
    </div>
    <div class="skeleton-bubble-row sent">
      <div class="skeleton-bubble glass-skeleton" style="width: 48%; height: 42px;"></div>
    </div>
  `;
}

export function renderConversationSkeletons(container) {
  if (!container) return;
  let html = '';
  for (let i = 0; i < 5; i++) {
    html += `
      <div class="skeleton-conv-item">
        <div class="skeleton-avatar glass-skeleton"></div>
        <div class="skeleton-lines">
          <div class="skeleton-line title glass-skeleton"></div>
          <div class="skeleton-line subtitle glass-skeleton"></div>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

export function renderConversationItem(conv, currentUserId, isActive = false, onlineUsers = new Set()) {
  const otherParticipant = conv.conversation_participants?.find(
    p => (p.user_id || p.users?.id) !== currentUserId
  )?.users || { username: conv.title || 'Unknown', avatar_color: '#007AFF' };

  const initial = escapeHtml((otherParticipant.username || '?')[0].toUpperCase());
  const rawColor = otherParticipant.avatar_color || '#007AFF';
  const color = /^#[0-9a-fA-F]{3,8}$/.test(rawColor) ? rawColor : '#007AFF';
  const isOnline = otherParticipant.id && onlineUsers ? onlineUsers.has(otherParticipant.id) : false;

  const div = document.createElement('div');
  div.className = `conv-item ${isActive ? 'active' : ''}`;
  div.dataset.convId = conv.id;
  div.dataset.targetUsername = otherParticipant.username;
  div.dataset.targetPublicKey = otherParticipant.public_key;
  div.setAttribute('role', 'button');
  div.setAttribute('tabindex', '0');
  div.setAttribute('aria-label', `Conversation with ${otherParticipant.username || 'Unknown'}`);

  div.innerHTML = `
    <div class="avatar" style="background-color: ${color}" aria-hidden="true">
      ${initial}
      <div class="avatar-status-badge ${isOnline ? '' : 'offline'}" id="status-badge-${otherParticipant.id || conv.id}"></div>
    </div>
    <div class="conv-item-content">
      <div class="conv-item-top">
        <span class="conv-item-name">${escapeHtml(otherParticipant.username)}</span>
        <span class="conv-item-time">${conv.updated_at ? formatTime(conv.updated_at) : ''}</span>
      </div>
      <div class="conv-item-bottom">
        <span class="conv-item-preview" id="conv-preview-${conv.id}">Encrypted chat</span>
      </div>
    </div>
  `;

  return div;
}

export function renderMessageBubble({ id, isMine, plainText, createdAt, isLastInCluster = true, isFailed = false, onRetry = null, isLive = false }) {
  const row = document.createElement('div');
  const liveClass = isLive ? (isMine ? 'live-sent' : 'live-received') : '';
  row.className = `message-row ${isMine ? 'sent' : 'received'} ${isLastInCluster ? 'has-tail' : 'clustered'} ${isFailed ? 'failed' : ''} ${liveClass}`.trim();
  row.id = `msg-${id}`;
  row.dataset.timestamp = new Date(createdAt).getTime();

  const isJumbo = isEmojiOnly(plainText);
  const formattedText = linkify(escapeHtml(plainText));
  const formattedTime = formatTime(createdAt);

  const tailSvg = (isLastInCluster && !isJumbo) ? `
    <svg class="bubble-tail" viewBox="0 0 9 16" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
      <path d="M0,0 C1,5 3.5,12 8.5,15.2 C9,15.6 8.5,16 7,16 L0,16 Z"/>
    </svg>
  ` : '';

  const deliveryBadgeHtml = isMine ? (
    isFailed ? `
      <span class="delivery-badge failed retry-btn" role="button" tabindex="0" title="Not Delivered. Tap to retry.">
        <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
        </svg>
        <span>Not Delivered • Retry</span>
      </span>
    ` : `
      <span class="delivery-badge" title="Delivered">
        <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
          <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
        </svg>
      </span>
    `
  ) : '';

  row.innerHTML = `
    <div class="message-content-wrapper">
      <div class="bubble ${isJumbo ? 'is-emoji-only' : ''}">
        ${formattedText}
        ${tailSvg}
      </div>
      <div class="message-actions">
        <button class="message-action-btn copy-msg-btn" type="button" title="Copy message" aria-label="Copy message text">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
          </svg>
        </button>
      </div>
    </div>
    <div class="bubble-meta">
      <span>${formattedTime}</span>
      ${deliveryBadgeHtml}
    </div>
  `;

  const bubbleEl = row.querySelector('.bubble');
  const copyBtn = row.querySelector('.copy-msg-btn');
  const retryBtn = row.querySelector('.retry-btn');

  if (retryBtn && typeof onRetry === 'function') {
    const handleRetry = (e) => {
      e.stopPropagation();
      onRetry(plainText, row);
    };
    retryBtn.addEventListener('click', handleRetry);
    retryBtn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleRetry(e);
      }
    });
  }

  const executeCopy = async () => {
    try {
      await navigator.clipboard.writeText(plainText);
      triggerHaptic('medium');
      showToast('Copied to clipboard', 1800);
      if (copyBtn) {
        copyBtn.classList.add('copied');
        copyBtn.innerHTML = `
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
          </svg>
        `;
        setTimeout(() => {
          copyBtn.classList.remove('copied');
          copyBtn.innerHTML = `
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
            </svg>
          `;
        }, 1600);
      }
    } catch (err) {
      console.warn('Clipboard copy error:', err);
    }
  };

  if (copyBtn) {
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      executeCopy();
    });
  }

  // Mobile double-tap to copy
  let lastTapTime = 0;
  if (bubbleEl) {
    bubbleEl.addEventListener('touchend', (e) => {
      const now = Date.now();
      if (now - lastTapTime < 320 && now - lastTapTime > 0) {
        e.preventDefault();
        executeCopy();
      }
      lastTapTime = now;
    });
  }

  return row;
}

export function renderTypingIndicator(username) {
  const div = document.createElement('div');
  div.id = 'active-typing-indicator';
  div.className = 'typing-bubble';
  div.title = `${username} is typing...`;
  div.innerHTML = `
    <div class="typing-dot"></div>
    <div class="typing-dot"></div>
    <div class="typing-dot"></div>
  `;
  return div;
}

export function removeTypingIndicator(immediate = false) {
  const existing = document.getElementById('active-typing-indicator');
  if (!existing) return;
  if (immediate) {
    existing.remove();
    return;
  }
  if (existing.classList.contains('collapsing')) return;
  existing.classList.add('collapsing');
  const cleanup = () => {
    if (existing.parentNode) existing.remove();
  };
  existing.addEventListener('animationend', cleanup, { once: true });
  setTimeout(cleanup, 250);
}

export function scrollToBottom(element, smooth = true) {
  if (!element) return;
  requestAnimationFrame(() => {
    element.scrollTo({
      top: element.scrollHeight,
      behavior: smooth ? 'smooth' : 'auto'
    });
  });
}
