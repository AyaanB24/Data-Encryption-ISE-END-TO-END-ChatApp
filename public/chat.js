
import { generateRSAKeyPair, encryptAESKey, decryptAESKey } from './utils/rsa.js';
import { generateAESKey, exportAESKey, importAESKey, encryptMessage, decryptMessage } from './utils/aes.js';

// --- CONFIGURATION ---
// These should match your Pusher dashboard
const PUSHER_KEY = '9619457411b436b0306b';
const PUSHER_CLUSTER = 'ap2';

let pusher = null;
let presenceChannel = null;
let privateChannel = null;

// State
let myUsername = '';
let myRSAPrivateKey = null;
let myRSAPublicKey = '';
let activeChatPartner = null;
let chatPartners = new Map();
let messageHistory = new Map();
let myId = '';

// DOM Elements
const setupContainer = document.getElementById('setup-container');
const chatContainer = document.getElementById('chat-container');
const usernameInput = document.getElementById('username-input');
const joinBtn = document.getElementById('join-btn');
const userListEl = document.getElementById('user-list');
const messagesEl = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const chatHeader = document.getElementById('chat-header');
const logEntries = document.getElementById('log-entries');

// Utility to log security events
function securityLog(message, type = '') {
    const entry = document.createElement('p');
    const time = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    entry.innerHTML = `<span class="log-time">[${time}]</span> <span class="${type}">${message}</span>`;
    logEntries.prepend(entry);
}

// Initialize RSA Keys on page load
async function initKeys() {
    securityLog("Generating 2048-bit RSA Key Pair...", "log-success");
    const keys = await generateRSAKeyPair();
    myRSAPrivateKey = keys.privateKey;
    myRSAPublicKey = keys.publicKey;
    securityLog("RSA Keys Ready (Public Key shared on Join)");
    joinBtn.disabled = false;
    joinBtn.textContent = "Join Chat";
}

joinBtn.textContent = "Generating Keys...";
joinBtn.disabled = true;
initKeys();

// Join Chat
joinBtn.addEventListener('click', () => {
    myUsername = usernameInput.value.trim();
    if (!myUsername) return alert("Please enter a username");

    // Initialize Pusher
    pusher = new Pusher(PUSHER_KEY, {
        cluster: PUSHER_CLUSTER,
        authEndpoint: '/pusher/auth',
        auth: {
            params: {
                username: myUsername,
                publicKey: myRSAPublicKey
            }
        }
    });

    // Subscribe to Presence Channel
    presenceChannel = pusher.subscribe('presence-chat');

    presenceChannel.bind('pusher:subscription_succeeded', () => {
        myId = presenceChannel.members.me.id;
        setupContainer.classList.add('hidden');
        chatContainer.classList.remove('hidden');
        securityLog(`Joined as ${myUsername}. RSA Public Key shared.`);
        updateUserList();
        
        // Subscribe to my own private channel for messages
        privateChannel = pusher.subscribe(`private-user-${myId}`);
        setupIncomingEvents();
    });

    presenceChannel.bind('pusher:member_added', () => updateUserList());
    presenceChannel.bind('pusher:member_removed', () => updateUserList());
});

function updateUserList() {
    userListEl.innerHTML = '';
    presenceChannel.members.each(member => {
        if (member.id === myId) return;

        const user = {
            id: member.id,
            username: member.info.username,
            publicKey: member.info.publicKey
        };

        const li = document.createElement('li');
        li.innerHTML = `
            <div style="width:40px;height:40px;background:#ddd;border-radius:50%;margin-right:15px;display:flex;align-items:center;justify-content:center;color:#666;font-weight:bold;">
                ${user.username[0].toUpperCase()}
            </div>
            <span>${user.username}</span>
        `;

        if (activeChatPartner && activeChatPartner.id === user.id) {
            li.classList.add('active');
        }

        li.onclick = () => selectUser(user);
        userListEl.appendChild(li);

        if (!chatPartners.has(user.id)) {
            chatPartners.set(user.id, { ...user, aesKey: null });
            messageHistory.set(user.id, []);
        } else {
            const existing = chatPartners.get(user.id);
            existing.username = user.username;
            existing.publicKey = user.publicKey;
        }
    });
}

function setupIncomingEvents() {
    // Receive AES Key
    privateChannel.bind('receive-aes-key', async ({ from, encryptedAESKey }) => {
        securityLog("Received encrypted AES key from partner.");
        securityLog("Decrypting AES key with MY RSA Private Key...", "log-encrypted");

        const rawAESKey = await decryptAESKey(encryptedAESKey, myRSAPrivateKey);
        const aesKey = await importAESKey(rawAESKey);

        if (chatPartners.has(from)) {
            chatPartners.get(from).aesKey = aesKey;
        } else {
            chatPartners.set(from, { aesKey });
            messageHistory.set(from, []);
        }
        securityLog("Secure AES-GCM channel established.", "log-success");
    });

    // Receive Message
    privateChannel.bind('receive-message', async ({ from, encryptedMsg }) => {
        const partner = chatPartners.get(from);
        if (!partner || !partner.aesKey) return;

        securityLog("Received encrypted packet.");
        securityLog(`Deciphering: ${encryptedMsg.ciphertext.substring(0, 25)}...`, "log-encrypted");

        const decryptedText = await decryptMessage(encryptedMsg, partner.aesKey);

        if (decryptedText !== "[Decryption Error or Tampered Message]") {
            securityLog("Integrity Verified (SHA-256 Match).", "log-success");
            securityLog(`Decrypted text: "${decryptedText}"`);
        } else {
            securityLog("INTEGRITY ERROR: Hash Mismatch!", "log-encrypted");
        }

        saveAndDisplayMessage(from, partner.username || 'Stranger', decryptedText, 'received');
    });
}

// Select a user to chat with
async function selectUser(user) {
    activeChatPartner = chatPartners.get(user.id);

    messagesEl.innerHTML = '';
    const history = messageHistory.get(user.id) || [];
    history.forEach(msg => displayMessage(msg.sender, msg.text, msg.type));

    chatHeader.textContent = user.username;
    messageInput.disabled = false;
    sendBtn.disabled = false;
    messageInput.focus();

    document.querySelectorAll('#user-list li').forEach(li => {
        li.classList.toggle('active', li.querySelector('span').textContent === user.username);
    });

    if (!activeChatPartner.aesKey) {
        securityLog(`Initiating Handshake with ${user.username}...`);
        const aesKey = await generateAESKey();
        activeChatPartner.aesKey = aesKey;

        securityLog("Exporting raw AES-256 key...");
        const rawAESKey = await exportAESKey(aesKey);

        securityLog("Encrypting AES key with recipient's RSA Public Key...", "log-encrypted");
        const encryptedAESKey = await encryptAESKey(rawAESKey, user.publicKey);

        // Share via API
        fetch('/api/share-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: user.id,
                from: myId,
                encryptedAESKey: encryptedAESKey
            })
        });
        securityLog("Shared encrypted AES key with partner.");
    }
}

// Send Message
sendBtn.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    if (!text || !activeChatPartner || !activeChatPartner.aesKey) return;

    securityLog(`Plaintext: "${text}"`);
    securityLog("Encrypting with AES-GCM (256-bit)...");

    const encryptedObj = await encryptMessage(text, activeChatPartner.aesKey);

    securityLog(`Ciphertext: ${encryptedObj.ciphertext.substring(0, 25)}...`, "log-encrypted");
    securityLog(`SHA-256 Hash Generated.`);

    // Send via API
    fetch('/api/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            to: activeChatPartner.id,
            from: myId,
            encryptedMsg: encryptedObj
        })
    });

    saveAndDisplayMessage(activeChatPartner.id, 'You', text, 'sent');
    messageInput.value = '';
});

function saveAndDisplayMessage(partnerId, sender, text, type) {
    const history = messageHistory.get(partnerId) || [];
    history.push({ sender, text, type });
    messageHistory.set(partnerId, history);
    if (activeChatPartner && activeChatPartner.id === partnerId) {
        displayMessage(sender, text, type);
    }
}

function displayMessage(sender, text, type) {
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${type}`;
    msgDiv.innerHTML = `<strong>${sender}</strong><span>${text}</span>`;
    if (text === "[Decryption Error or Tampered Message]") {
        msgDiv.innerHTML += `<span style="color:red;font-size:0.7rem;"> (Integrity Failure)</span>`;
    }
    messagesEl.appendChild(msgDiv);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendBtn.click();
});
