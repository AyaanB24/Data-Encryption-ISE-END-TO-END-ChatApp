
// utils/aes.js - AES Encryption for Messages and integrity hashing

export async function generateAESKey() {
    return await window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function exportAESKey(key) {
    const exported = await window.crypto.subtle.exportKey("raw", key);
    return exported; // ArrayBuffer
}

export async function importAESKey(keyBuffer) {
    return await window.crypto.subtle.importKey(
        "raw",
        keyBuffer,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"]
    );
}

export async function encryptMessage(message, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Hash for integrity
    const hash = await hashMessage(message);

    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        data
    );

    return {
        ciphertext: arrayBufferToBase64(encrypted),
        iv: arrayBufferToBase64(iv),
        hash: hash
    };
}

export async function decryptMessage(encryptedObj, key) {
    const ciphertext = base64ToArrayBuffer(encryptedObj.ciphertext);
    const iv = base64ToArrayBuffer(encryptedObj.iv);

    try {
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        const message = decoder.decode(decrypted);

        // Verify integrity
        const currentHash = await hashMessage(message);
        if (currentHash !== encryptedObj.hash) {
            throw new Error("Integrity check failed: Message tampered!");
        }

        return message;
    } catch (e) {
        console.error("Decryption failed", e);
        return "[Decryption Error or Tampered Message]";
    }
}

export async function hashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
    return arrayBufferToBase64(hashBuffer);
}

// Helper functions (same as RSA but isolated for modularity)
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}
