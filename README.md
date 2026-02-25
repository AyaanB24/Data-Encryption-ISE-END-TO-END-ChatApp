# SecureTalk: End-to-End Encrypted Chat Application 🔐

A minimalist, high-security real-time chat application demonstrating the power of hybrid encryption (RSA + AES) for academic and practical evaluation. This project focuses on ensuring that even if the server is compromised, message contents remain private.

## 🌟 Features
- **Real-time Messaging**: Instant communication using WebSockets (Socket.io).
- **End-to-End Encryption (E2EE)**: Messages are encrypted on the sender's device and decrypted only on the recipient's device.
- **Hybrid Cryptography**:
  - **RSA (Asymmetric)**: Used for secure exchange of session keys.
  - **AES (Symmetric)**: Used for high-speed encryption of actual message data.
- **Minimalist UI**: Clean, focus-oriented interface built with Vanilla CSS and HTML5.
- **Client-Side Processing**: All encryption and decryption logic happens in the browser, ensuring the server never sees plaintext messages.

## 🏗️ Technical Architecture

1. **Key Exchange (RSA)**:
   - Clients generate an RSA key pair upon joining.
   - Public keys are shared via the server.
   - A symmetric AES key is generated and shared securely using the recipient's RSA public key.
2. **Message Encryption (AES)**:
   - Once a secure channel is established, all messages are encrypted using the AES-256-GCM/CBC standard.
3. **Communication Layer**:
   - Node.js & Express server acting as a signaling and message relay hub.
   - Socket.io for low-latency, bidirectional event-based communication.

## 🛠️ Tech Stack
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (ES6+)
- **Backend**: Node.js, Express.js
- **Real-time**: Socket.io
- **Security**: Web Crypto API / Custom Crypto Utils

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v14 or later)
- npm (installed automatically with Node)

### Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/AyaanB24/Data-Encryption-ISE-END-TO-END-ChatApp.git
   cd Data-Encryption-ISE-END-TO-END-ChatApp
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the server**:
   ```bash
   npm start
   ```

4. **Access the app**:
   Open [http://localhost:3000](http://localhost:3000) in multiple browser tabs to start chatting securely.

## 📂 Project Structure
```text
├── public/
│   ├── index.html    # Main UI
│   ├── chat.js       # Client-side logic & socket handling
│   └── style.css     # Premium minimalist styling
├── utils/
│   ├── aes.js        # AES Encryption/Decryption utilities
│   └── rsa.js        # RSA Key generation and handling
├── server.js         # Express server & Socket.io relay
└── package.json      # Dependencies and scripts
```

## 📜 License
This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

---
*Created for ISE Data Encryption Evaluation.*
