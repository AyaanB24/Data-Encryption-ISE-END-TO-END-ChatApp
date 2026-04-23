
import { generateRSAKeyPair, encryptAESKey, decryptAESKey } from './utils/rsa.js';
import { generateAESKey, exportAESKey, importAESKey, encryptMessage, decryptMessage } from './utils/aes.js';

// --- CONFIGURATION ---
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

function securityLog(message, type = '') {
    const entry = document.createElement('p');
    const time = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    entry.innerHTML = `<span class="log-time">[${time}]</span> <span class="${type}">${message}</span>`;
    logEntries.prepend(entry);
}

async function initKeys() {
    securityLog("Generating 2048-bit RSA Key Pair...", "log-success");
    const keys = await generateRSAKeyPair();
    myRSAPrivateKey = keys.privateKey;
    myRSAPublicKey = keys.publicKey;
    securityLog("RSA Keys Ready.");
    joinBtn.disabled = false;
    joinBtn.textContent = "Join Chat";
}

joinBtn.textContent = "Generating Keys...";
joinBtn.disabled = true;
initKeys();

joinBtn.addEventListener('click', () => {
    myUsername = usernameInput.value.trim();
    if (!myUsername) return alert("Please enter a username");

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

    presenceChannel = pusher.subscribe('presence-chat');

    presenceChannel.bind('pusher:subscription_succeeded', () => {
        myId = presenceChannel.members.me.id;
        setupContainer.classList.add('hidden');
        chatContainer.classList.remove('hidden');
        securityLog(`Joined as ${myUsername}. ID: ${myId.substring(0,8)}...`, "log-success");
        updateUserList();
        
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

        const li = document.createElement('li');
        li.innerHTML = `
            <div style="width:40px;height:40px;background:#ddd;border-radius:50%;margin-right:15px;display:flex;align-items:center;justify-content:center;color:#666;font-weight:bold;">
                ${member.info.username[0].toUpperCase()}
            </div>
            <span>${member.info.username}</span>
        `;

        if (activeChatPartner && activeChatPartner.id === member.id) {
            li.classList.add('active');
        }

        li.onclick = () => selectUser({
            id: member.id,
            username: member.info.username,
            publicKey: member.info.publicKey
        });
        userListEl.appendChild(li);

        if (!chatPartners.has(member.id)) {
            chatPartners.set(member.id, { 
                id: member.id, 
                username: member.info.username, 
                publicKey: member.info.publicKey, 
                aesKey: null 
            });
            messageHistory.set(member.id, []);
        }
    });
}

function setupIncomingEvents() {
    privateChannel.bind('receive-aes-key', async ({ from, encryptedAESKey }) => {
        securityLog(`Key Handshake received from ${from.substring(0,8)}...`);
        try {
            const rawAESKey = await decryptAESKey(encryptedAESKey, myRSAPrivateKey);
            const aesKey = await importAESKey(rawAESKey);

            if (!chatPartners.has(from)) {
                chatPartners.set(from, { id: from, aesKey: aesKey });
                messageHistory.set(from, []);
            } else {
                chatPartners.get(from).aesKey = aesKey;
            }
            securityLog("Handshake Complete: Secure Channel Established.", "log-success");
        } catch (err) {
            securityLog("Handshake Failed: RSA Decryption Error.", "log-encrypted");
            console.error(err);
        }
    });

    privateChannel.bind('receive-message', async ({ from, encryptedMsg }) => {
        const partner = chatPartners.get(from);
        if (!partner || !partner.aesKey) {
            securityLog("Error: Received message before handshake was complete.", "log-encrypted");
            return;
        }

        securityLog("Received encrypted packet. Deciphering...");
        const decryptedText = await decryptMessage(encryptedMsg, partner.aesKey);

        if (decryptedText === "[Decryption Error or Tampered Message]") {
            securityLog("SECURITY ALERT: Integrity Failure or Key Mismatch!", "log-encrypted");
        } else {
            securityLog("Integrity Verified (SHA-256 Match).", "log-success");
        }

        saveAndDisplayMessage(from, partner.username || 'Stranger', decryptedText, 'received');
    });
}

async function selectUser(user) {
    activeChatPartner = chatPartners.get(user.id);
    if (!activeChatPartner) {
        chatPartners.set(user.id, { ...user, aesKey: null });
        activeChatPartner = chatPartners.get(user.id);
    }

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

    // If we don't have a shared key yet, generate one and send it
    if (!activeChatPartner.aesKey) {
        securityLog(`Initiating Handshake with ${user.username}...`);
        const aesKey = await generateAESKey();
        activeChatPartner.aesKey = aesKey;

        const rawAESKey = await exportAESKey(aesKey);
        const encryptedAESKey = await encryptAESKey(rawAESKey, user.publicKey);

        fetch('/api/share-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: user.id,
                from: myId,
                encryptedAESKey: encryptedAESKey
            })
        });
        securityLog("AES Key generated and shared via RSA.", "log-success");
    }
}

sendBtn.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    if (!text || !activeChatPartner || !activeChatPartner.aesKey) return;

    securityLog("Encrypting message with AES-GCM...");
    const encryptedObj = await encryptMessage(text, activeChatPartner.aesKey);

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
        msgDiv.style.background = "#fff0f0";
        msgDiv.style.border = "1px solid #ffcccc";
    }
    messagesEl.appendChild(msgDiv);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendBtn.click();
});
