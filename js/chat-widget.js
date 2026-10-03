/**
 * Supinkly.AI — Live Chat Widget (Customer Side)
 * WebSocket real-time chat with admin
 */

const CHAT = (() => {
    const WS_URL = (() => {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const host  = location.hostname === 'localhost' || location.hostname === '127.0.0.1'
            ? `${location.hostname}:3000`
            : location.host;
        return `${proto}://${host}/ws/chat`;
    })();

    let ws = null;
    let sessionId = null;
    let typingTimer = null;
    let reconnectTimer = null;
    let opened = false;
    let unreadCount = 0;

    function escapeHTML(str) {
        if (!str && str !== 0) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    /* ── Inject widget HTML ───────────────────────────────────────── */
    function injectWidget() {
        const el = document.createElement('div');
        el.id = 'spk-chat-root';
        el.innerHTML = `
        <!-- Bubble Button -->
        <button id="spk-chat-btn"
            class="fixed bottom-20 right-3.5 sm:bottom-6 sm:right-6 z-40 w-12 h-12 sm:w-14 sm:h-14 rounded-full gradient-btn shadow-xl hover:scale-110 active:scale-95 transition-all flex items-center justify-center touch-active"
            title="แชทกับเราได้เลย" aria-label="เปิดแชท">
            <i id="spk-chat-icon" class="fa-solid fa-comment-dots text-xl sm:text-2xl text-white"></i>
            <span id="spk-chat-badge"
                class="hidden absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-500 border-2 border-white text-white text-[10px] font-bold flex items-center justify-center">
            </span>
        </button>

        <!-- Chat Window -->
        <div id="spk-chat-window"
            class="hidden fixed inset-x-2 bottom-20 sm:inset-x-auto sm:bottom-24 sm:right-6 sm:w-96 z-50 flex flex-col rounded-2xl sm:rounded-3xl overflow-hidden shadow-2xl border border-slate-200 bg-white"
            style="max-height: calc(100vh - 100px);">

            <!-- Header -->
            <div class="gradient-btn px-4 py-3.5 flex items-center justify-between gap-3 shrink-0">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 rounded-2xl bg-white/20 flex items-center justify-center text-white text-lg shrink-0">
                        <i class="fa-solid fa-headset"></i>
                    </div>
                    <div>
                        <div class="text-white font-bold text-sm leading-tight">แชทสดกับแอดมิน</div>
                        <div id="spk-chat-status" class="text-white/80 text-[11px] font-medium flex items-center gap-1">
                            <span id="spk-status-dot" class="w-1.5 h-1.5 rounded-full bg-white/50 inline-block"></span>
                            <span id="spk-status-text">กำลังเชื่อมต่อ...</span>
                        </div>
                    </div>
                </div>
                <button id="spk-chat-close" class="text-white/80 hover:text-white text-xl leading-none p-1 transition-colors" aria-label="ปิด">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>

            <!-- Name input (shown before auth) -->
            <div id="spk-name-form" class="p-4 border-b border-slate-100 bg-slate-50">
                <p class="text-xs font-bold text-slate-700 mb-2">กรอกชื่อเพื่อเริ่มแชท</p>
                <div class="flex gap-2">
                    <input id="spk-name-input" type="text" maxlength="40"
                        placeholder="ชื่อของคุณ เช่น สมชาย..."
                        class="flex-1 px-3 py-2 rounded-xl border-2 border-slate-200 focus:border-pink-500 text-sm font-medium outline-none transition-colors">
                    <button id="spk-name-btn"
                        class="px-4 py-2 rounded-xl gradient-btn text-white text-xs font-bold shrink-0 hover:opacity-90 transition-opacity">
                        เริ่มแชท
                    </button>
                </div>
            </div>

            <!-- Messages -->
            <div id="spk-messages"
                class="flex-1 overflow-y-auto p-4 space-y-3 bg-slate-50/60"
                style="min-height: 200px; max-height: 280px;">
                <div id="spk-welcome-msg" class="text-center">
                    <div class="inline-block px-3 py-1.5 rounded-full bg-slate-100 text-slate-500 text-xs font-medium">
                        👋 สวัสดีครับ! มีอะไรให้ช่วยไหม?
                    </div>
                </div>
            </div>

            <!-- Typing indicator -->
            <div id="spk-typing" class="hidden px-4 py-1 text-[11px] text-slate-400 font-medium italic bg-white border-t border-slate-100">
                แอดมินกำลังพิมพ์...
            </div>

            <!-- Input -->
            <div id="spk-input-area" class="hidden px-3 py-3 bg-white border-t border-slate-200 flex items-end gap-2 shrink-0">
                <textarea id="spk-msg-input"
                    placeholder="พิมพ์ข้อความ..."
                    rows="1"
                    class="flex-1 px-3 py-2.5 rounded-2xl border-2 border-slate-200 focus:border-pink-500 text-sm font-medium outline-none resize-none transition-colors leading-snug"
                    style="max-height: 100px;"></textarea>
                <button id="spk-send-btn"
                    class="w-10 h-10 rounded-2xl gradient-btn text-white flex items-center justify-center shrink-0 hover:opacity-90 transition-opacity disabled:opacity-40">
                    <i class="fa-solid fa-paper-plane text-sm"></i>
                </button>
            </div>
        </div>`;
        document.body.appendChild(el);
    }

    /* ── Time formatter ───────────────────────────────────────────── */
    function fmtTime(ts) {
        return new Date(ts).toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' });
    }

    /* ── Append message bubble ────────────────────────────────────── */
    function appendMsg({ from, text, ts, own, name }) {
        const msgs = document.getElementById('spk-messages');
        if (!msgs) return;

        const isOwn = own || from === 'customer';
        const isAdmin = from === 'admin';

        const wrap = document.createElement('div');
        wrap.className = `flex ${isOwn ? 'justify-end' : 'justify-start'} gap-2`;

        const bubble = document.createElement('div');
        bubble.className = `max-w-[80%] px-3.5 py-2.5 rounded-2xl text-sm font-medium leading-relaxed shadow-xs
            ${isOwn
                ? 'bg-gradient-to-br from-pink-500 to-purple-600 text-white rounded-br-md'
                : isAdmin
                    ? 'bg-white border border-slate-200 text-slate-900 rounded-bl-md'
                    : 'bg-white border border-slate-200 text-slate-900 rounded-bl-md'}`;

        bubble.innerHTML = `
            ${isAdmin ? `<div class="text-[10px] font-bold text-pink-600 mb-0.5 flex items-center gap-1"><i class="fa-solid fa-headset text-[9px]"></i> แอดมิน</div>` : ''}
            <div class="whitespace-pre-wrap break-words">${escapeHTML(text)}</div>
            <div class="text-[10px] mt-1 ${isOwn ? 'text-white/60 text-right' : 'text-slate-400'}">${fmtTime(ts || Date.now())}</div>
        `;
        wrap.appendChild(bubble);
        msgs.appendChild(wrap);
        msgs.scrollTop = msgs.scrollHeight;

        // Unread badge
        const win = document.getElementById('spk-chat-window');
        if (win && win.classList.contains('hidden') && !isOwn) {
            unreadCount++;
            updateBadge();
        }
    }

    function updateBadge() {
        const badge = document.getElementById('spk-chat-badge');
        if (!badge) return;
        if (unreadCount > 0) {
            badge.textContent = unreadCount > 9 ? '9+' : unreadCount;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    function setStatus(text, online) {
        const dot  = document.getElementById('spk-status-dot');
        const span = document.getElementById('spk-status-text');
        if (dot)  dot.className  = `w-1.5 h-1.5 rounded-full inline-block ${online ? 'bg-emerald-400 animate-pulse' : 'bg-white/40'}`;
        if (span) span.textContent = text;
    }

    function appendSystem(text) {
        const msgs = document.getElementById('spk-messages');
        if (!msgs) return;
        const d = document.createElement('div');
        d.className = 'text-center';
        d.innerHTML = `<span class="inline-block px-3 py-1 rounded-full bg-slate-100 text-slate-400 text-[11px] font-medium">${escapeHTML(text)}</span>`;
        msgs.appendChild(d);
        msgs.scrollTop = msgs.scrollHeight;
    }

    /* ── WebSocket ────────────────────────────────────────────────── */
    function connect(name) {
        if (ws && ws.readyState < 2) return;
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'auth', role: 'customer', name }));
            if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        };

        ws.onmessage = ({ data }) => {
            let msg;
            try { msg = JSON.parse(data); } catch { return; }

            if (msg.type === 'session')     { sessionId = msg.sessionId; }
            if (msg.type === 'auth_ok')     {
                setStatus(msg.adminOnline ? 'แอดมินออนไลน์ พร้อมตอบ 🟢' : 'รอแอดมิน... (จะตอบเร็วๆ นี้)', msg.adminOnline);
                document.getElementById('spk-name-form').classList.add('hidden');
                document.getElementById('spk-input-area').classList.remove('hidden');
            }
            if (msg.type === 'admin_status') setStatus(msg.online ? 'แอดมินออนไลน์ พร้อมตอบ 🟢' : 'รอแอดมิน... (จะตอบเร็วๆ นี้)', msg.online);
            if (msg.type === 'message')      {
                appendMsg(msg);
                // clear typing
                document.getElementById('spk-typing').classList.add('hidden');
            }
            if (msg.type === 'typing') {
                const el = document.getElementById('spk-typing');
                if (el) el.classList.remove('hidden');
                setTimeout(() => el && el.classList.add('hidden'), 3000);
            }
        };

        ws.onclose = () => {
            setStatus('การเชื่อมต่อขาด กำลังต่อใหม่...', false);
            reconnectTimer = setTimeout(() => {
                const nameInput = document.getElementById('spk-name-input');
                const savedName = nameInput?.dataset.savedName;
                if (savedName) connect(savedName);
            }, 3000);
        };

        ws.onerror = () => ws.close();
    }

    function sendMsg() {
        const inp = document.getElementById('spk-msg-input');
        const text = (inp?.value || '').trim();
        if (!text || !ws || ws.readyState !== 1) return;
        ws.send(JSON.stringify({ type: 'message', text }));
        inp.value = '';
        inp.style.height = '';
    }

    /* ── Init ─────────────────────────────────────────────────────── */
    function init() {
        injectWidget();

        const btn    = document.getElementById('spk-chat-btn');
        const win    = document.getElementById('spk-chat-window');
        const close  = document.getElementById('spk-chat-close');
        const nameBtn = document.getElementById('spk-name-btn');
        const nameInp = document.getElementById('spk-name-input');
        const msgInp  = document.getElementById('spk-msg-input');
        const sendBtn = document.getElementById('spk-send-btn');

        btn.addEventListener('click', () => {
            opened = !opened;
            win.classList.toggle('hidden', !opened);
            if (opened) {
                unreadCount = 0;
                updateBadge();
                msgInp?.focus();
            }
        });
        close.addEventListener('click', () => {
            opened = false;
            win.classList.add('hidden');
        });

        // Start chat (auth as customer)
        const startChat = () => {
            const name = nameInp.value.trim() || 'ลูกค้า';
            nameInp.dataset.savedName = name;
            connect(name);
        };
        nameBtn.addEventListener('click', startChat);
        nameInp.addEventListener('keydown', e => { if (e.key === 'Enter') startChat(); });

        // Auto-resize textarea
        msgInp.addEventListener('input', () => {
            msgInp.style.height = '';
            msgInp.style.height = Math.min(msgInp.scrollHeight, 100) + 'px';
            // Typing signal
            if (ws && ws.readyState === 1) {
                clearTimeout(typingTimer);
                ws.send(JSON.stringify({ type: 'typing' }));
                typingTimer = setTimeout(() => {}, 2000);
            }
        });

        sendBtn.addEventListener('click', sendMsg);
        msgInp.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
        });
    }

    return { init };
})();

// Boot when DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => CHAT.init());
} else {
    CHAT.init();
}
