
// utils/rsa.js - RSA Encryption for Key Exchange

export async function generateRSAKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
        publicKey: arrayBufferToBase64(publicKey),
        privateKey: keyPair.privateKey // Keep as CryptoKey object for local decryption
    };
}

export async function encryptAESKey(aesKeyBuffer, publicKeyBase64) {
    const publicKeyBuffer = base64ToArrayBuffer(publicKeyBase64);
    const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );

    const encryptedKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        aesKeyBuffer
    );

    return arrayBufferToBase64(encryptedKey);
}

export async function decryptAESKey(encryptedKeyBase64, privateKey) {
    const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKeyBase64);
    
    // If it's a string, we need to import it (but usually we keep the private key as CryptoKey object)
    // For this project, we'll keep privateKey as the CryptoKey object in memory.

    const decryptedKeyBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKeyBuffer
    );

    return decryptedKeyBuffer;
}

// Helper functions
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
