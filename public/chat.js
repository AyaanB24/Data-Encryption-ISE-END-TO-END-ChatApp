
import { generateRSAKeyPair, encryptAESKey, decryptAESKey } from '/utils/rsa.js';
import { generateAESKey, exportAESKey, importAESKey, encryptMessage, decryptMessage } from '/utils/aes.js';

const socket = io();

// State
let myUsername = '';
let myRSAPrivateKey = null;
let myRSAPublicKey = '';
let activeChatPartner = null;
let chatPartners = new Map();
let messageHistory = new Map();

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

    socket.emit('join', {
        username: myUsername,
        publicKey: myRSAPublicKey
    });

    setupContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    securityLog(`Joined as ${myUsername}. RSA Public Key shared.`);
});

// Update User List
socket.on('user-list', (users) => {
    userListEl.innerHTML = '';
    users.forEach(user => {
        if (user.id === socket.id) return;

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

        if (chatPartners.has(user.id)) {
            const existing = chatPartners.get(user.id);
            existing.username = user.username;
            existing.publicKey = user.publicKey;
        } else {
            chatPartners.set(user.id, { ...user, aesKey: null });
            messageHistory.set(user.id, []);
        }
    });
});

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

        socket.emit('share-aes-key', {
            to: user.id,
            encryptedAESKey: encryptedAESKey
        });
        securityLog("Shared encrypted AES key with partner.");
    }
}

// Receive AES Key
socket.on('receive-aes-key', async ({ from, encryptedAESKey }) => {
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

// Send Message
sendBtn.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    if (!text || !activeChatPartner || !activeChatPartner.aesKey) return;

    securityLog(`Plaintext: "${text}"`);
    securityLog("Encrypting with AES-GCM (256-bit)...");

    const encryptedObj = await encryptMessage(text, activeChatPartner.aesKey);

    securityLog(`Ciphertext: ${encryptedObj.ciphertext.substring(0, 25)}...`, "log-encrypted");
    securityLog(`SHA-256 Hash Generated.`);

    socket.emit('chat-message', {
        to: activeChatPartner.id,
        encryptedMsg: encryptedObj
    });

    saveAndDisplayMessage(activeChatPartner.id, 'You', text, 'sent');
    messageInput.value = '';
});

// Receive Message
socket.on('receive-message', async ({ from, encryptedMsg }) => {
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
